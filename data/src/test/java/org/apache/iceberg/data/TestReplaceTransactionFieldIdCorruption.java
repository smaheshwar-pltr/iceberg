/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.iceberg.data;

import static org.apache.iceberg.types.Types.NestedField.optional;
import static org.apache.iceberg.types.Types.NestedField.required;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import org.apache.hadoop.conf.Configuration;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.DataFile;
import org.apache.iceberg.FileFormat;
import org.apache.iceberg.PartitionSpec;
import org.apache.iceberg.Schema;
import org.apache.iceberg.Table;
import org.apache.iceberg.Transaction;
import org.apache.iceberg.catalog.Namespace;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.hadoop.HadoopCatalog;
import org.apache.iceberg.io.DataWriter;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableMap;
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.apache.iceberg.types.Types;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests that verify field IDs are preserved during replace transaction rebase with concurrent
 * schema-changing replaces. Uses {@code buildReplacementPreservingIds} to ensure data files written
 * during the transaction remain readable after rebase, even when the concurrent replace uses a
 * completely different schema.
 */
public class TestReplaceTransactionFieldIdCorruption {

  private static final Configuration CONF = new Configuration();
  private static final Namespace NS = Namespace.of("db");

  @TempDir private File tempDir;

  private HadoopCatalog catalog;

  @BeforeEach
  public void before() {
    catalog = new HadoopCatalog();
    catalog.setConf(CONF);
    catalog.initialize(
        "test-catalog",
        ImmutableMap.of(CatalogProperties.WAREHOUSE_LOCATION, tempDir.getAbsolutePath()));
  }

  /**
   * Verifies that required fields remain readable after rebase. With buildReplacementPreservingIds,
   * the field IDs from the original replace transaction are preserved, so the Parquet file's field
   * IDs still match the table schema.
   */
  @Test
  public void testRequiredFieldReadableAfterRebase() throws IOException {
    TableIdentifier tableId = TableIdentifier.of(NS, "required_field_test");

    Schema originalSchema =
        new Schema(
            required(1, "id", Types.IntegerType.get()),
            required(2, "data", Types.StringType.get()));

    Schema differentSchema =
        new Schema(
            required(1, "id", Types.IntegerType.get()),
            required(2, "category", Types.StringType.get()));

    catalog.createTable(tableId, originalSchema);

    Transaction txnA = catalog.buildTable(tableId, originalSchema).replaceTransaction();
    Table txnTable = txnA.table();
    DataFile dataFile = writeDataFile(txnTable, originalSchema, 42, "hello");
    txnA.newFastAppend().appendFile(dataFile).commit();

    // Concurrently replace with a different schema
    Transaction concurrentReplace =
        catalog.buildTable(tableId, differentSchema).replaceTransaction();
    concurrentReplace.commitTransaction();

    // Commit the first replace — rebase preserves field IDs
    txnA.commitTransaction();

    Table finalTable = catalog.loadTable(tableId);
    Types.NestedField dataField = finalTable.schema().findField("data");
    assertThat(dataField).as("data field should exist in final schema").isNotNull();

    // Field ID must be preserved — the rebase uses buildReplacementPreservingIds
    assertThat(dataField.fieldId())
        .as("data field should retain its original ID after rebase")
        .isEqualTo(2);

    // Data should be fully readable since field IDs match the Parquet file
    List<Record> records = Lists.newArrayList(IcebergGenerics.read(finalTable).build());
    assertThat(records).hasSize(1);
    assertThat(records.get(0).getField("id")).isEqualTo(42);
    assertThat(records.get(0).getField("data")).isEqualTo("hello");
  }

  /**
   * Verifies that optional fields are readable (not null) after rebase with a concurrent
   * schema-changing replace.
   */
  @Test
  public void testOptionalFieldReadableAfterRebase() throws IOException {
    TableIdentifier tableId = TableIdentifier.of(NS, "optional_field_test");

    Schema originalSchema =
        new Schema(
            required(1, "id", Types.IntegerType.get()),
            optional(2, "data", Types.StringType.get()));

    Schema differentSchema =
        new Schema(
            required(1, "id", Types.IntegerType.get()),
            optional(2, "category", Types.StringType.get()));

    catalog.createTable(tableId, originalSchema);

    Transaction txnA = catalog.buildTable(tableId, originalSchema).replaceTransaction();
    Table txnTable = txnA.table();
    DataFile dataFile = writeDataFile(txnTable, originalSchema, 42, "hello");
    txnA.newFastAppend().appendFile(dataFile).commit();

    Transaction concurrentReplace =
        catalog.buildTable(tableId, differentSchema).replaceTransaction();
    concurrentReplace.commitTransaction();

    txnA.commitTransaction();

    Table finalTable = catalog.loadTable(tableId);
    Types.NestedField dataField = finalTable.schema().findField("data");
    assertThat(dataField).as("data field should exist in final schema").isNotNull();
    assertThat(dataField.fieldId())
        .as("data field should retain its original ID after rebase")
        .isEqualTo(2);

    // Data should be readable — not null
    List<Record> records = Lists.newArrayList(IcebergGenerics.read(finalTable).build());
    assertThat(records).hasSize(1);
    assertThat(records.get(0).getField("id")).isEqualTo(42);
    assertThat(records.get(0).getField("data"))
        .as("data should be 'hello', not null — field IDs are preserved")
        .isEqualTo("hello");
  }

  /**
   * Verifies that data remains readable after rebase when the concurrent replace uses a schema with
   * completely different column names at the same positions.
   */
  @Test
  public void testDataReadableAfterConcurrentColumnRename() throws IOException {
    TableIdentifier tableId = TableIdentifier.of(NS, "column_addition_test");

    Schema originalSchema =
        new Schema(
            required(1, "id", Types.IntegerType.get()),
            optional(2, "data", Types.StringType.get()));

    Schema schemaWithExtraColumn =
        new Schema(
            required(1, "id", Types.IntegerType.get()),
            optional(2, "extra_col", Types.LongType.get()));

    catalog.createTable(tableId, originalSchema);

    Transaction txnA = catalog.buildTable(tableId, originalSchema).replaceTransaction();
    Table txnTable = txnA.table();
    DataFile dataFile = writeDataFile(txnTable, originalSchema, 99, "world");
    txnA.newFastAppend().appendFile(dataFile).commit();

    Transaction concurrentReplace =
        catalog.buildTable(tableId, schemaWithExtraColumn).replaceTransaction();
    concurrentReplace.commitTransaction();

    txnA.commitTransaction();

    Table finalTable = catalog.loadTable(tableId);
    Types.NestedField dataField = finalTable.schema().findField("data");
    assertThat(dataField).as("data field should exist").isNotNull();
    assertThat(dataField.fieldId())
        .as("data field should retain its original ID after rebase")
        .isEqualTo(2);

    // Data should be readable
    List<Record> records = Lists.newArrayList(IcebergGenerics.read(finalTable).build());
    assertThat(records).hasSize(1);
    assertThat(records.get(0).getField("id")).isEqualTo(99);
    assertThat(records.get(0).getField("data"))
        .as("data should be 'world', not null — field IDs are preserved")
        .isEqualTo("world");
  }

  private DataFile writeDataFile(Table table, Schema writeSchema, int id, String data)
      throws IOException {
    Record record = GenericRecord.create(writeSchema);
    record.setField("id", id);
    record.setField("data", data);

    String filename = FileFormat.PARQUET.addExtension("test-" + UUID.randomUUID());
    File dataDir = new File(tempDir, "data");
    dataDir.mkdirs();
    File file = new File(dataDir, filename);

    GenericFileWriterFactory writerFactory =
        new GenericFileWriterFactory.Builder(table).dataFileFormat(FileFormat.PARQUET).build();

    DataWriter<Record> writer =
        writerFactory.newDataWriter(
            FileHelpers.encrypt(org.apache.iceberg.Files.localOutput(file)),
            PartitionSpec.unpartitioned(),
            null);

    try (writer) {
      writer.write(record);
    }

    return writer.toDataFile();
  }
}
