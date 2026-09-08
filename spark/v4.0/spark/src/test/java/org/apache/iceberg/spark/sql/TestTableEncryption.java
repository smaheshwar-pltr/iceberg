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
package org.apache.iceberg.spark.sql;

import static org.apache.iceberg.Files.localInput;
import static org.apache.iceberg.types.Types.NestedField.optional;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.io.FileUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.ChecksumFileSystem;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.iceberg.AppendFiles;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.DataFile;
import org.apache.iceberg.DeleteFile;
import org.apache.iceberg.FileFormat;
import org.apache.iceberg.FileScanTask;
import org.apache.iceberg.HasTableOperations;
import org.apache.iceberg.ManifestContent;
import org.apache.iceberg.ManifestFile;
import org.apache.iceberg.ManifestFiles;
import org.apache.iceberg.ManifestReader;
import org.apache.iceberg.MetadataTableType;
import org.apache.iceberg.Parameters;
import org.apache.iceberg.RewriteTablePathUtil;
import org.apache.iceberg.Schema;
import org.apache.iceberg.Snapshot;
import org.apache.iceberg.Table;
import org.apache.iceberg.TableMetadata;
import org.apache.iceberg.Transaction;
import org.apache.iceberg.actions.RewriteTablePath;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.deletes.BaseDVFileWriter;
import org.apache.iceberg.deletes.DVFileWriter;
import org.apache.iceberg.encryption.Ciphers;
import org.apache.iceberg.encryption.EncryptionUtil;
import org.apache.iceberg.encryption.UnitestKMS;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFileFactory;
import org.apache.iceberg.io.SeekableInputStream;
import org.apache.iceberg.parquet.Parquet;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableList;
import org.apache.iceberg.relocated.com.google.common.collect.Maps;
import org.apache.iceberg.relocated.com.google.common.collect.Streams;
import org.apache.iceberg.spark.CatalogTestBase;
import org.apache.iceberg.spark.SparkCatalogConfig;
import org.apache.iceberg.spark.actions.SparkActions;
import org.apache.iceberg.types.Types;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.spark.SparkException;
import org.apache.spark.sql.Row;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.mockito.internal.util.collections.Iterables;

public class TestTableEncryption extends CatalogTestBase {
  private static Map<String, String> appendCatalogEncryptionProperties(Map<String, String> props) {
    Map<String, String> newProps = Maps.newHashMap();
    newProps.putAll(props);
    newProps.put(CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getCanonicalName());
    return newProps;
  }

  @Parameters(name = "catalogName = {0}, implementation = {1}, config = {2}")
  protected static Object[][] parameters() {
    return new Object[][] {
      {
        SparkCatalogConfig.HIVE.catalogName(),
        SparkCatalogConfig.HIVE.implementation(),
        appendCatalogEncryptionProperties(SparkCatalogConfig.HIVE.properties())
      }
    };
  }

  @BeforeEach
  public void createTables() {
    sql(
        "CREATE TABLE %s (id bigint, data string, float float) USING iceberg "
            + "TBLPROPERTIES ( "
            + "'encryption.key-id'='%s', 'format-version'='3')",
        tableName, UnitestKMS.MASTER_KEY_NAME1);

    sql("INSERT INTO %s VALUES (1, 'a', 1.0), (2, 'b', 2.0), (3, 'c', float('NaN'))", tableName);
  }

  @AfterEach
  public void removeTables() {
    sql("DROP TABLE IF EXISTS %s", tableName);
    sql("DROP TABLE IF EXISTS %s", tableName("rewritten_table"));
  }

  @TestTemplate
  public void testSelect() {
    List<Object[]> expected =
        ImmutableList.of(row(1L, "a", 1.0F), row(2L, "b", 2.0F), row(3L, "c", Float.NaN));

    assertEquals("Should return all expected rows", expected, sql("SELECT * FROM %s", tableName));
  }

  @TestTemplate
  public void rewriteTablePathPreservesEncryption() throws Exception {
    String shufflePartitions = spark.conf().get("spark.sql.shuffle.partitions");
    try {
      spark.conf().set("spark.sql.shuffle.partitions", "4");
      assertRewriteTablePathPreservesEncryption();
    } finally {
      spark.conf().set("spark.sql.shuffle.partitions", shufflePartitions);
    }
  }

  private void assertRewriteTablePathPreservesEncryption() throws Exception {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);
    String targetLocation = temp.resolve("rewrite-table-path-target").toUri().toString();
    String stagingLocation = temp.resolve("rewrite-table-path-staging").toUri().toString();

    addPositionDelete(table);
    table.refresh();
    sql("REFRESH TABLE %s", tableName);
    List<Object[]> expected = sql("SELECT * FROM %s ORDER BY id", tableName);
    int sourceKeyCount = EncryptionUtil.encryptionKeys(table.encryption()).size();

    RewriteTablePath.Result result =
        SparkActions.get()
            .rewriteTablePath(table)
            .rewriteLocationPrefix(table.location(), targetLocation)
            .stagingLocation(stagingLocation)
            .execute();
    assertThat(EncryptionUtil.encryptionKeys(table.encryption())).hasSize(sourceKeyCount);

    copyTableFiles(result);
    String targetMetadataLocation =
        RewriteTablePathUtil.combinePaths(targetLocation, "metadata/" + result.latestVersion());
    TableIdentifier targetIdent = TableIdentifier.of("default", "rewritten_table");
    validationCatalog.registerTable(targetIdent, targetMetadataLocation);

    assertEquals(
        "Should read all rows from the rewritten table",
        expected,
        sql("SELECT * FROM %s ORDER BY id", tableName("rewritten_table")));

    Table rewrittenTable = validationCatalog.loadTable(targetIdent);
    TableMetadata rewrittenMetadata = ((HasTableOperations) rewrittenTable).operations().current();
    assertThat(rewrittenTable.currentSnapshot().keyId())
        .isNotEqualTo(table.currentSnapshot().keyId());
    assertThat(rewrittenMetadata.encryptionKeys())
        .anyMatch(key -> key.keyId().equals(rewrittenTable.currentSnapshot().keyId()));
    assertEncryptedMetadataFiles(rewrittenTable);
    Map<Long, String> targetSnapshotKeyIDs =
        Streams.stream(rewrittenTable.snapshots())
            .collect(Collectors.toMap(Snapshot::snapshotId, Snapshot::keyId));

    sql("INSERT INTO %s VALUES (4, 'd', 4.0)", tableName);
    table.refresh();
    RewriteTablePath.Result incrementalResult =
        SparkActions.get()
            .rewriteTablePath(table)
            .rewriteLocationPrefix(table.location(), targetLocation)
            .stagingLocation(temp.resolve("incremental-staging").toUri().toString())
            .startVersion(result.latestVersion())
            .execute();
    copyTableFiles(incrementalResult);

    sql("DROP TABLE %s", tableName("rewritten_table"));
    validationCatalog.registerTable(
        targetIdent,
        RewriteTablePathUtil.combinePaths(
            targetLocation, "metadata/" + incrementalResult.latestVersion()));
    assertEquals(
        "Should read all rows after an incremental rewrite",
        sql("SELECT * FROM %s ORDER BY id", tableName),
        sql("SELECT * FROM %s ORDER BY id", tableName("rewritten_table")));

    Table incrementalTable = validationCatalog.loadTable(targetIdent);
    Map<Long, String> incrementalSnapshotKeyIDs =
        Streams.stream(incrementalTable.snapshots())
            .collect(Collectors.toMap(Snapshot::snapshotId, Snapshot::keyId));
    assertThat(incrementalSnapshotKeyIDs).containsAllEntriesOf(targetSnapshotKeyIDs);
    assertThat(((HasTableOperations) incrementalTable).operations().current().encryptionKeys())
        .extracting(key -> key.keyId())
        .containsAll(targetSnapshotKeyIDs.values());
    assertEncryptedMetadataFiles(incrementalTable);
  }

  @TestTemplate
  public void encryptedIncrementalRewriteRequiresTargetStartVersion() {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);
    String startVersion =
        RewriteTablePathUtil.fileName(
            ((HasTableOperations) table).operations().current().metadataFileLocation());
    File stagingDir = temp.resolve("missing-target-staging").toFile();

    assertThatThrownBy(
            () ->
                SparkActions.get()
                    .rewriteTablePath(table)
                    .rewriteLocationPrefix(
                        table.location(), temp.resolve("missing-target").toUri().toString())
                    .stagingLocation(stagingDir.toURI().toString())
                    .startVersion(startVersion)
                    .execute())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Cannot find target start version file");
    assertThat(stagingDir).doesNotExist();
  }

  private void assertEncryptedMetadataFiles(Table table) throws IOException {
    checkMetadataFileEncryption(localInput(table.currentSnapshot().manifestListLocation()));
    boolean foundDeleteFile = false;
    for (ManifestFile manifest : table.currentSnapshot().allManifests(table.io())) {
      checkMetadataFileEncryption(localInput(manifest.path()));
      if (manifest.content() == ManifestContent.DELETES) {
        try (ManifestReader<DeleteFile> reader =
            ManifestFiles.readDeleteManifest(manifest, table.io(), table.specs())) {
          for (DeleteFile deleteFile : reader) {
            foundDeleteFile = true;
            assertThat(deleteFile.keyMetadata()).isNotNull();
            checkMetadataFileEncryption(localInput(deleteFile.location()));
          }
        }
      }
    }
    assertThat(foundDeleteFile).isTrue();
  }

  private void addPositionDelete(Table table) throws IOException {
    DataFile dataFile = currentDataFiles(table).get(0);
    OutputFileFactory fileFactory =
        OutputFileFactory.builderFor(table, 1, 1).format(FileFormat.PUFFIN).build();
    DVFileWriter writer = new BaseDVFileWriter(fileFactory, path -> null);
    try (writer) {
      writer.delete(dataFile.location(), 0L, table.spec(), dataFile.partition());
    }

    table.newRowDelta().addDeletes(writer.result().deleteFiles().get(0)).commit();
  }

  private void copyTableFiles(RewriteTablePath.Result result) throws IOException {
    for (Row filePair :
        spark.read().format("csv").load(result.fileListLocation()).collectAsList()) {
      FileUtils.copyFile(
          new File(URI.create(filePair.getString(0))), new File(URI.create(filePair.getString(1))));
    }
  }

  private static List<DataFile> currentDataFiles(Table table) {
    return Streams.stream(table.newScan().planFiles())
        .map(FileScanTask::file)
        .collect(Collectors.toList());
  }

  @TestTemplate
  public void testRefresh() {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);

    assertThat(currentDataFiles(table)).isNotEmpty();

    sql("INSERT INTO %s VALUES (4, 'd', 4.0), (5, 'e', 5.0), (6, 'f', float('NaN'))", tableName);

    table.refresh();
    assertThat(currentDataFiles(table)).isNotEmpty();
  }

  @TestTemplate
  public void testAppendTransaction() {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);

    List<DataFile> dataFiles = currentDataFiles(table);
    Transaction transaction = table.newTransaction();
    AppendFiles append = transaction.newAppend();

    // add an arbitrary datafile
    append.appendFile(dataFiles.get(0));
    append.commit();
    transaction.commitTransaction();

    assertThat(currentDataFiles(table)).hasSize(dataFiles.size() + 1);
  }

  @TestTemplate
  public void testConcurrentAppendTransactions() {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);

    List<DataFile> dataFiles = currentDataFiles(table);
    Transaction transaction = table.newTransaction();
    AppendFiles append = transaction.newAppend();

    // add an arbitrary datafile
    append.appendFile(dataFiles.get(0));

    // append to the table in the meantime. use a separate load to avoid shared operations
    validationCatalog.loadTable(tableIdent).newFastAppend().appendFile(dataFiles.get(0)).commit();

    append.commit();
    transaction.commitTransaction();

    assertThat(currentDataFiles(table)).hasSize(dataFiles.size() + 2);
  }

  // See CatalogTests#testConcurrentReplaceTransactions
  @TestTemplate
  public void testConcurrentReplaceTransactions() {
    validationCatalog.initialize(catalogName, catalogConfig);

    Table table = validationCatalog.loadTable(tableIdent);
    DataFile file = currentDataFiles(table).get(0);
    Schema schema = table.schema();

    // Write data for a replace transaction that will be committed later
    Transaction secondReplace =
        validationCatalog
            .buildTable(tableIdent, schema)
            .withProperty("encryption.key-id", UnitestKMS.MASTER_KEY_NAME1)
            .replaceTransaction();
    secondReplace.newFastAppend().appendFile(file).commit();

    // Commit another replace transaction first
    Transaction firstReplace =
        validationCatalog
            .buildTable(tableIdent, schema)
            .withProperty("encryption.key-id", UnitestKMS.MASTER_KEY_NAME1)
            .replaceTransaction();
    firstReplace.newFastAppend().appendFile(file).commit();
    firstReplace.commitTransaction();

    secondReplace.commitTransaction();

    Table afterSecondReplace = validationCatalog.loadTable(tableIdent);
    assertThat(currentDataFiles(afterSecondReplace)).hasSize(1);
  }

  @TestTemplate
  public void testInsertAndDelete() {
    sql("INSERT INTO %s VALUES (4, 'd', 4.0), (5, 'e', 5.0), (6, 'f', float('NaN'))", tableName);

    List<Object[]> expected =
        ImmutableList.of(
            row(1L, "a", 1.0F),
            row(2L, "b", 2.0F),
            row(3L, "c", Float.NaN),
            row(4L, "d", 4.0F),
            row(5L, "e", 5.0F),
            row(6L, "f", Float.NaN));

    assertEquals(
        "Should return all expected rows",
        expected,
        sql("SELECT * FROM %s ORDER BY id", tableName));

    sql("DELETE FROM %s WHERE id < 4", tableName);

    expected = ImmutableList.of(row(4L, "d", 4.0F), row(5L, "e", 5.0F), row(6L, "f", Float.NaN));

    assertEquals(
        "Should return all expected rows",
        expected,
        sql("SELECT * FROM %s ORDER BY id", tableName));
  }

  @TestTemplate
  public void testMetadataTamperproofing() throws IOException {
    ChecksumFileSystem fs = ((ChecksumFileSystem) FileSystem.newInstance(new Configuration()));
    catalog.initialize(catalogName, catalogConfig);

    Table table = catalog.loadTable(tableIdent);
    TableMetadata currentMetadata = ((HasTableOperations) table).operations().current();
    Path metadataFile = new Path(currentMetadata.metadataFileLocation());
    Path previousMetadataFile = new Path(Iterables.firstOf(currentMetadata.previousFiles()).file());

    // manual FS tampering: replacing the current metadata file with a previous one
    Path crcPath = fs.getChecksumFile(metadataFile);
    fs.delete(crcPath, false);
    fs.delete(metadataFile, false);
    fs.rename(previousMetadataFile, metadataFile);

    assertThatThrownBy(() -> catalog.loadTable(tableIdent))
        .hasMessageContaining(
            String.format(
                "The current metadata file %s might have been modified. Hash of metadata loaded from storage differs from HMS-stored metadata hash.",
                metadataFile));
  }

  @TestTemplate
  public void testKeyDelete() {
    assertThatThrownBy(
            () -> sql("ALTER TABLE %s UNSET TBLPROPERTIES (`encryption.key-id`)", tableName))
        .isInstanceOf(SparkException.class)
        .hasMessage("Unsupported table change: Cannot remove key ID from an encrypted table");
  }

  @TestTemplate
  public void testKeyAlter() {
    assertThatThrownBy(
            () -> sql("ALTER TABLE %s SET TBLPROPERTIES ('encryption.key-id'='abcd')", tableName))
        .isInstanceOf(SparkException.class)
        .hasMessage("Unsupported table change: Cannot modify key ID of an encrypted table");
  }

  @TestTemplate
  public void testReplaceKeyChange() {
    // Replacing a table with a different encryption key is disallowed
    assertThatThrownBy(
            () ->
                sql(
                    "REPLACE TABLE %s (id bigint) USING iceberg TBLPROPERTIES ('encryption.key-id'='%s')",
                    tableName, UnitestKMS.MASTER_KEY_NAME2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot modify key ID of an encrypted table");
  }

  @TestTemplate
  public void testDirectDataFileRead() {
    List<Object[]> dataFileTable =
        sql("SELECT file_path FROM %s.%s", tableName, MetadataTableType.ALL_DATA_FILES);
    List<String> dataFiles =
        Streams.concat(dataFileTable.stream())
            .map(row -> (String) row[0])
            .collect(Collectors.toList());

    if (dataFiles.isEmpty()) {
      throw new RuntimeException("No data files found for table " + tableName);
    }

    Schema schema = new Schema(optional(0, "id", Types.IntegerType.get()));
    for (String filePath : dataFiles) {
      assertThatThrownBy(
              () ->
                  Parquet.read(localInput(filePath))
                      .project(schema)
                      .callInit()
                      .build()
                      .iterator()
                      .next())
          .isInstanceOf(ParquetCryptoRuntimeException.class)
          .hasMessageContaining("Trying to read file with encrypted footer. No keys available");
    }
  }

  @TestTemplate
  public void testManifestEncryption() throws IOException {
    List<Object[]> manifestFileTable =
        sql("SELECT path FROM %s.%s", tableName, MetadataTableType.MANIFESTS);

    List<String> manifestFiles =
        Streams.concat(manifestFileTable.stream())
            .map(row -> (String) row[0])
            .collect(Collectors.toList());

    if (manifestFiles.isEmpty()) {
      throw new RuntimeException("No manifest files found for table " + tableName);
    }

    String metadataFolderPath = null;

    // Check encryption of manifest files
    for (String manifestFilePath : manifestFiles) {
      checkMetadataFileEncryption(localInput(manifestFilePath));

      if (metadataFolderPath == null) {
        metadataFolderPath = new File(manifestFilePath).getParent().replaceFirst("file:", "");
      }
    }

    if (metadataFolderPath == null) {
      throw new RuntimeException("No metadata folder found for table " + tableName);
    }

    // Find manifest list and metadata files; check their encryption
    File[] listOfMetadataFiles = new File(metadataFolderPath).listFiles();
    boolean foundManifestListFile = false;

    for (File metadataFile : listOfMetadataFiles) {
      if (metadataFile.getName().startsWith("snap-")) {
        foundManifestListFile = true;
        checkMetadataFileEncryption(localInput(metadataFile));
      }
    }

    if (!foundManifestListFile) {
      throw new RuntimeException("No manifest list files found for table " + tableName);
    }
  }

  @TestTemplate
  public void testDropTableWithPurge() {
    List<Object[]> dataFileTable =
        sql("SELECT file_path FROM %s.%s", tableName, MetadataTableType.ALL_DATA_FILES);
    List<String> dataFiles =
        Streams.concat(dataFileTable.stream())
            .map(row -> (String) row[0])
            .collect(Collectors.toList());
    assertThat(dataFiles).isNotEmpty();
    assertThat(dataFiles)
        .allSatisfy(filePath -> assertThat(localInput(filePath).exists()).isTrue());

    sql("DROP TABLE %s PURGE", tableName);

    assertThat(catalog.tableExists(tableIdent)).as("Table should not exist").isFalse();
    assertThat(dataFiles)
        .allSatisfy(filePath -> assertThat(localInput(filePath).exists()).isFalse());
  }

  private void checkMetadataFileEncryption(InputFile file) throws IOException {
    SeekableInputStream stream = file.newStream();
    byte[] magic = new byte[4];
    stream.read(magic);
    stream.close();
    assertThat(magic).isEqualTo(Ciphers.GCM_STREAM_MAGIC_STRING.getBytes(StandardCharsets.UTF_8));
  }
}
