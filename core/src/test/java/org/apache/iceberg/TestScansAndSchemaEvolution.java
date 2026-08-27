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
package org.apache.iceberg;

import static org.apache.iceberg.TestHelpers.ALL_VERSIONS;
import static org.apache.iceberg.TestHelpers.V3_AND_ABOVE;
import static org.apache.iceberg.types.Types.NestedField.required;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.avro.generic.GenericData;
import org.apache.iceberg.avro.Avro;
import org.apache.iceberg.avro.RandomAvroData;
import org.apache.iceberg.exceptions.ValidationException;
import org.apache.iceberg.expressions.Expressions;
import org.apache.iceberg.expressions.Literal;
import org.apache.iceberg.inmemory.InMemoryOutputFile;
import org.apache.iceberg.io.FileAppender;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.apache.iceberg.transforms.Transforms;
import org.apache.iceberg.types.Types;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

@ExtendWith(ParameterizedTestExtension.class)
public class TestScansAndSchemaEvolution {
  private static final Schema SCHEMA =
      new Schema(
          required(1, "id", Types.LongType.get()),
          required(2, "data", Types.StringType.get()),
          required(3, "part", Types.StringType.get()));

  private static final PartitionSpec SPEC =
      PartitionSpec.builderFor(SCHEMA).identity("part").build();

  @Parameters(name = "formatVersion = {0}")
  protected static List<Integer> formatVersions() {
    return ALL_VERSIONS;
  }

  @Parameter private int formatVersion;

  @TempDir private File temp;

  private DataFile createDataFile(String partValue) throws IOException {
    return createDataFile(partValue, SCHEMA, SPEC);
  }

  private DataFile createDataFile(String partValue, Schema schema, PartitionSpec spec)
      throws IOException {
    List<GenericData.Record> expected = RandomAvroData.generate(schema, 100, 0L);

    OutputFile dataFile =
        new InMemoryOutputFile(FileFormat.AVRO.addExtension(UUID.randomUUID().toString()));
    try (FileAppender<GenericData.Record> writer =
        Avro.write(dataFile).schema(schema).named("test").build()) {
      for (GenericData.Record rec : expected) {
        rec.put("part", partValue); // create just one partition
        writer.add(rec);
      }
    }

    PartitionData partition = new PartitionData(spec.partitionType());
    partition.set(0, partValue);
    return DataFiles.builder(spec)
        .withInputFile(dataFile.toInputFile())
        .withPartition(partition)
        .withRecordCount(100)
        .build();
  }

  @AfterEach
  public void cleanupTables() {
    TestTables.clearTables();
  }

  @TestTemplate
  public void testPartitionSourceRename() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    DataFile fileOne = createDataFile("one");
    DataFile fileTwo = createDataFile("two");

    table.newAppend().appendFile(fileOne).appendFile(fileTwo).commit();
    long firstSnapshotId = table.currentSnapshot().snapshotId();

    List<FileScanTask> tasks =
        Lists.newArrayList(table.newScan().filter(Expressions.equal("part", "one")).planFiles());

    assertThat(tasks).hasSize(1);

    table.updateSchema().renameColumn("part", "p").commit();

    // plan the scan using the new name in a filter
    tasks = Lists.newArrayList(table.newScan().filter(Expressions.equal("p", "one")).planFiles());

    assertThat(tasks).hasSize(1);

    // create a new commit
    table.newAppend().appendFile(createDataFile("three")).commit();

    // use fiter with previous partition name
    tasks =
        Lists.newArrayList(
            table
                .newScan()
                .useSnapshot(firstSnapshotId)
                .filter(Expressions.equal("part", "one"))
                .planFiles());

    assertThat(tasks).hasSize(1);
  }

  @TestTemplate
  public void testPartitionSourceAdd() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    DataFile fileOne = createDataFile("one");
    DataFile fileTwo = createDataFile("two");

    table.newAppend().appendFile(fileOne).appendFile(fileTwo).commit();
    long firstSnapshotId = table.currentSnapshot().snapshotId();

    List<FileScanTask> tasks =
        Lists.newArrayList(table.newScan().filter(Expressions.equal("part", "one")).planFiles());

    assertThat(tasks).hasSize(1);

    // add a new partition column
    table.updateSchema().addColumn("hour", Types.IntegerType.get()).commit();
    table.updateSpec().addField("hour").commit();

    // plan the scan using the new column in a filter
    tasks = Lists.newArrayList(table.newScan().filter(Expressions.isNull("hour")).planFiles());

    assertThat(tasks).hasSize(2);

    // create a new commit
    table.newAppend().appendFile(createDataFile("three")).commit();

    // plan the scan using the existing column in a filter
    tasks =
        Lists.newArrayList(
            table
                .newScan()
                .useSnapshot(firstSnapshotId)
                .filter(Expressions.equal("part", "one"))
                .planFiles());

    assertThat(tasks).hasSize(1);
  }

  @TestTemplate
  public void testPartitionSourceDrop() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    DataFile fileOne = createDataFile("one");
    DataFile fileTwo = createDataFile("two");

    table.newAppend().appendFile(fileOne).appendFile(fileTwo).commit();
    long firstSnapshotId = table.currentSnapshot().snapshotId();

    table.updateSpec().addField("id").commit();

    List<FileScanTask> tasks =
        Lists.newArrayList(
            table.newScan().filter(Expressions.not(Expressions.isNull("id"))).planFiles());

    assertThat(tasks).hasSize(2);

    DataFile fileThree = createDataFile("three", table.schema(), table.spec());
    table.newAppend().appendFile(fileThree).commit();

    // remove one field from spec and drop the column
    table.updateSpec().removeField("id").commit();
    table.updateSchema().deleteColumn("id").commit();

    List<FileScanTask> tasksAtFirstSnapshotId =
        Lists.newArrayList(
            table
                .newScan()
                .useSnapshot(firstSnapshotId)
                .filter(Expressions.not(Expressions.isNull("id")))
                .planFiles());

    assertThat(
            tasksAtFirstSnapshotId.stream()
                .map(ContentScanTask::file)
                .map(ContentFile::location)
                .collect(Collectors.toList()))
        .isEqualTo(
            tasks.stream()
                .map(ContentScanTask::file)
                .map(ContentFile::location)
                .collect(Collectors.toList()));
  }

  @TestTemplate
  public void testColumnAdd() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    DataFile fileOne = createDataFile("one");
    DataFile fileTwo = createDataFile("two");

    table.newAppend().appendFile(fileOne).appendFile(fileTwo).commit();
    long firstSnapshotId = table.currentSnapshot().snapshotId();

    table.updateSchema().addColumn("hour", Types.IntegerType.get()).commit();

    DataFile fileThree = createDataFile("three", table.schema(), table.spec());
    table.newAppend().appendFile(fileThree).commit();

    // plan the scan using the new column in a filter
    List<FileScanTask> tasks =
        Lists.newArrayList(table.newScan().filter(Expressions.isNull("hour")).planFiles());
    assertThat(tasks).hasSize(3);

    // plan the scan using the existing column in a filter
    tasks =
        Lists.newArrayList(
            table
                .newScan()
                .useSnapshot(firstSnapshotId)
                .filter(Expressions.equal("data", "xyz"))
                .planFiles());
    assertThat(tasks).hasSize(2);
  }

  @TestTemplate
  public void testColumnRename() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    DataFile fileOne = createDataFile("one");
    DataFile fileTwo = createDataFile("two");

    table.newAppend().appendFile(fileOne).appendFile(fileTwo).commit();
    long firstSnapshotId = table.currentSnapshot().snapshotId();

    table.updateSchema().renameColumn("data", "renamed_data").commit();

    DataFile fileThree = createDataFile("three", table.schema(), table.spec());
    table.newAppend().appendFile(fileThree).commit();
    long secondSnapshotId = table.currentSnapshot().snapshotId();

    // generate a new commit
    DataFile fileFour = createDataFile("four", table.schema(), table.spec());
    table.newAppend().appendFile(fileFour).commit();

    // running successfully with the new filter on previous column name
    List<FileScanTask> tasks =
        Lists.newArrayList(
            table
                .newScan()
                .useSnapshot(firstSnapshotId)
                .filter(Expressions.equal("data", "xyz"))
                .planFiles());
    assertThat(tasks).hasSize(2);

    // running successfully with the new filter on renamed column name
    tasks =
        Lists.newArrayList(
            table
                .newScan()
                .useSnapshot(secondSnapshotId)
                .filter(Expressions.equal("renamed_data", "xyz"))
                .planFiles());
    assertThat(tasks).hasSize(3);
  }

  @TestTemplate
  public void testColumnDrop() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    DataFile fileOne = createDataFile("one");
    DataFile fileTwo = createDataFile("two");

    table.newAppend().appendFile(fileOne).appendFile(fileTwo).commit();
    long firstSnapshotId = table.currentSnapshot().snapshotId();

    table.updateSchema().deleteColumn("data").commit();

    // make sure generating a new commit after dropping a column
    DataFile fileThree = createDataFile("three", table.schema(), table.spec());
    table.newAppend().appendFile(fileThree).commit();

    // running successfully with the new filter on previous column name
    List<FileScanTask> tasks =
        Lists.newArrayList(
            table
                .newScan()
                .useSnapshot(firstSnapshotId)
                .filter(Expressions.equal("data", "xyz"))
                .planFiles());
    assertThat(tasks).hasSize(2);
  }

  @TestTemplate
  public void timeTravelDoesNotDependOnUnrelatedCommits() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);
    table.newAppend().appendFile(createDataFile("one")).commit();
    long snapshotId = table.currentSnapshot().snapshotId();

    // a schema-only change creates no snapshot, so snapshotId is still the current snapshot
    table.updateSchema().deleteColumn("data").commit();

    // "data" existed in this snapshot, so a filter on it resolves in the snapshot's schema
    assertThat(
            Lists.newArrayList(
                table
                    .newScan()
                    .useSnapshot(snapshotId, BindingSchema.SNAPSHOT)
                    .filter(Expressions.equal("data", "xyz"))
                    .planFiles()))
        .hasSize(1);

    // an unrelated writer appends. Nothing about the selected snapshot or its schema changed.
    table.newAppend().appendFile(createDataFile("two", table.schema(), table.spec())).commit();

    // the identical scan still succeeds, which it did not before this was the caller's choice
    assertThat(
            Lists.newArrayList(
                table
                    .newScan()
                    .useSnapshot(snapshotId, BindingSchema.SNAPSHOT)
                    .filter(Expressions.equal("data", "xyz"))
                    .planFiles()))
        .hasSize(1);
  }

  @TestTemplate
  public void pinnedSnapshotResolvesNamesInTheTableSchema() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);
    table.newAppend().appendFile(createDataFile("one")).commit();
    long snapshotId = table.currentSnapshot().snapshotId();

    // a schema-only change, so the pinned snapshot does not record the new column
    table.updateSchema().addColumn("extra", Types.IntegerType.get()).commit();

    // a pin freezes the file set without moving the schema, so "extra" still resolves
    assertThat(
            Lists.newArrayList(
                table
                    .newScan()
                    .useSnapshot(snapshotId, BindingSchema.TABLE)
                    .filter(Expressions.isNull("extra"))
                    .planFiles()))
        .hasSize(1);

    // and the old column is gone from a pinned read once it is dropped
    table.updateSchema().deleteColumn("data").commit();
    assertThatThrownBy(
            () ->
                Lists.newArrayList(
                    table
                        .newScan()
                        .useSnapshot(snapshotId, BindingSchema.TABLE)
                        .filter(Expressions.equal("data", "xyz"))
                        .planFiles()))
        .isInstanceOf(ValidationException.class)
        .hasMessageContaining("Cannot find field 'data'");
  }

  @TestTemplate
  public void plansBranchSnapshotWhenMainIsEmpty() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    table.newAppend().appendFile(createDataFile("one")).toBranch("branch").commit();
    long snapshotId = table.snapshot("branch").snapshotId();
    assertThat(table.currentSnapshot()).isNull();

    table.updateSchema().deleteColumn("data").commit();

    assertThat(
            Lists.newArrayList(
                table
                    .newScan()
                    .useSnapshot(snapshotId, BindingSchema.SNAPSHOT)
                    .filter(Expressions.equal("data", "xyz"))
                    .planFiles()))
        .hasSize(1);
  }

  @TestTemplate
  public void metadataScansCannotUseTheSnapshotSchema() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);
    table.newAppend().appendFile(createDataFile("one")).commit();
    long snapshotId = table.currentSnapshot().snapshotId();

    Table filesTable =
        MetadataTableUtils.createMetadataTableInstance(table, MetadataTableType.FILES);

    // a metadata table's schema is derived, not the table's data schema, so there is no snapshot
    // schema to resolve against
    assertThatThrownBy(() -> filesTable.newScan().useSnapshot(snapshotId, BindingSchema.SNAPSHOT))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Cannot use the snapshot schema");

    // the table binding schema is what these scans already do
    assertThat(filesTable.newScan().useSnapshot(snapshotId, BindingSchema.TABLE).schema())
        .isNotNull();
  }

  @TestTemplate
  public void planningIgnoresSpecsAddedAfterTheSelectedSnapshot() throws IOException {
    // an unpartitioned table, so the name swap below is not blocked by an existing spec
    Schema schema =
        new Schema(
            required(1, "a", Types.StringType.get()), required(2, "b", Types.StringType.get()));
    Table table =
        TestTables.create(temp, "test", schema, PartitionSpec.unpartitioned(), formatVersion);

    table.newAppend().appendFile(dataFile(table.spec(), null)).commit();
    long snapshotId = table.currentSnapshot().snapshotId();

    // swap the two column names. field IDs are unchanged, so "a" now refers to field 2.
    table.updateSchema().renameColumn("a", "c").commit();
    table.updateSchema().renameColumn("b", "a").commit();

    // spec 1 partitions by the new "a", which is field 2. In the selected snapshot's schema, the
    // name "a" resolves to field 1 instead, so binding this spec to that schema fails. The selected
    // snapshot cannot reference spec 1, so planning must not bind it.
    table.updateSpec().addField("a").commit();
    table.newAppend().appendFile(dataFile(table.spec(), "x")).commit();

    assertThat(table.snapshot(snapshotId).dataManifests(table.io()))
        .allMatch(manifest -> manifest.partitionSpecId() == 0);

    List<FileScanTask> tasks =
        Lists.newArrayList(table.newScan().useSnapshot(snapshotId).planFiles());
    assertThat(tasks).hasSize(1);
  }

  @TestTemplate
  public void planningBindsSpecsWhoseSourceColumnWasDropped() throws IOException {
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    table.newAppend().appendFile(createDataFile("one")).commit();

    // dropping the partition field and then its source column is allowed, and leaves spec 0
    // referencing a column that no longer exists in any later schema
    table.updateSpec().removeField("part").commit();
    table.updateSchema().deleteColumn("part").commit();

    table.newAppend().appendFile(dataFile(table.spec(), null)).commit();
    long snapshotId = table.currentSnapshot().snapshotId();
    table.newAppend().appendFile(dataFile(table.spec(), null)).commit();

    // spec 0 is still referenced by manifests carried into this snapshot, so it is bound. It only
    // binds because missing source fields are tolerated.
    assertThat(specIdsIn(table.snapshot(snapshotId).dataManifests(table.io()))).contains(0);

    List<FileScanTask> tasks =
        Lists.newArrayList(table.newScan().useSnapshot(snapshotId).planFiles());
    assertThat(tasks).hasSize(2);
  }

  private static Set<Integer> specIdsIn(List<ManifestFile> manifests) {
    return manifests.stream().map(ManifestFile::partitionSpecId).collect(Collectors.toSet());
  }

  private DataFile dataFile(PartitionSpec spec, String partValue) {
    DataFiles.Builder builder =
        DataFiles.builder(spec)
            .withPath("/path/to/" + UUID.randomUUID() + ".parquet")
            .withFileSizeInBytes(10)
            .withRecordCount(100);

    if (!spec.fields().isEmpty()) {
      PartitionData partition = new PartitionData(spec.partitionType());
      partition.set(0, partValue);
      builder.withPartition(partition);
    }

    return builder.build();
  }

  @TestTemplate
  public void testAddColumnWithDefaultValueAndQuery() throws IOException {
    assumeThat(V3_AND_ABOVE).as("Default values require v3+").contains(formatVersion);
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    // Write initial data
    DataFile fileOne = createDataFile("one");
    DataFile fileTwo = createDataFile("two");
    table.newAppend().appendFile(fileOne).appendFile(fileTwo).commit();

    // Add a new column with an initial default value
    String defaultValue = "default_category";
    table
        .updateSchema()
        .addColumn("category", Types.StringType.get(), "Product category", Literal.of(defaultValue))
        .commit();

    // Verify the schema includes the new column with default value
    Schema updatedSchema = table.schema();
    Types.NestedField categoryField = updatedSchema.findField("category");
    assertThat(categoryField).isNotNull();
    assertThat(categoryField.initialDefault()).isEqualTo(defaultValue);
    assertThat(categoryField.writeDefault()).isEqualTo(defaultValue);

    // Verify scan planning works with the new column that has default value
    assertThat(table.newScan().planFiles()).hasSize(2);

    // Test that scan with projection includes the new column with default value
    Schema projectionSchema = table.schema().select("id", "data", "category");
    assertThat(table.newScan().project(projectionSchema).planFiles())
        .hasSize(2)
        .allSatisfy(
            task -> {
              assertThat(task.schema().findField("category")).isNotNull();
              assertThat(task.schema().findField("category").initialDefault())
                  .isEqualTo(defaultValue);
            });

    // Test scan with filter on the new default column
    assertThat(table.newScan().filter(Expressions.equal("category", defaultValue)).planFiles())
        .hasSize(2); // All files should match since default applies to all

    // Test scan with filter on a value that is different than default.
    assertThat(table.newScan().filter(Expressions.equal("category", "non_default")).planFiles())
        .hasSize(2); // Files are returned, filtering happens during read

    // Write new data after schema evolution
    DataFile fileThree = createDataFile("three");
    table.newAppend().appendFile(fileThree).commit();

    // Test that all tasks have access to the column with default value
    assertThat(table.newScan().planFiles())
        .hasSize(3)
        .allSatisfy(
            task -> {
              Schema taskSchema = task.schema();
              Types.NestedField categoryFieldInTask = taskSchema.findField("category");
              assertThat(categoryFieldInTask).isNotNull();
              assertThat(categoryFieldInTask.initialDefault()).isEqualTo(defaultValue);
              assertThat(categoryFieldInTask.writeDefault()).isEqualTo(defaultValue);
            });
  }

  @TestTemplate
  public void testAddColumnWithDefaultValueAndPartitionTransform() throws IOException {
    assumeThat(V3_AND_ABOVE).as("Default values require v3+").contains(formatVersion);
    Table table = TestTables.create(temp, "test", SCHEMA, SPEC, formatVersion);

    // Write initial data
    DataFile fileOne = createDataFile("one");
    DataFile fileTwo = createDataFile("two");
    table.newAppend().appendFile(fileOne).appendFile(fileTwo).commit();

    // Add a new column with an initial default value
    String defaultValue = "default_category";
    table
        .updateSchema()
        .addColumn("category", Types.StringType.get(), "Product category", Literal.of(defaultValue))
        .commit();

    // Add bucket transform on the new column with default value
    table.updateSpec().addField(Expressions.bucket("category", 8)).commit();

    // Verify the updated partition spec includes the new column with bucket transform
    PartitionSpec updatedSpec = table.spec();
    assertThat(updatedSpec.fields())
        .hasSize(2); // original "part" (identity) + new "category_bucket_8"

    // Verify original identity partition field is preserved
    PartitionField partPartitionField = updatedSpec.fields().get(0);
    assertThat(partPartitionField.name()).isEqualTo("part");
    assertThat(partPartitionField.transform()).isEqualTo(Transforms.identity());

    // Verify new bucket partition field
    PartitionField categoryPartitionField = updatedSpec.fields().get(1);
    assertThat(categoryPartitionField.name()).isEqualTo("category_bucket_8");
    assertThat(categoryPartitionField.transform()).isEqualTo(Transforms.bucket(8));

    // Verify scan planning works with the new partition column
    assertThat(table.newScan().planFiles()).hasSize(2);

    // Test that scan with projection includes the new column with default value
    Schema projectionSchema = table.schema().select("id", "data", "category");
    assertThat(table.newScan().project(projectionSchema).planFiles())
        .hasSize(2)
        .allSatisfy(
            task -> {
              assertThat(task.schema().findField("category")).isNotNull();
              assertThat(task.schema().findField("category").initialDefault())
                  .isEqualTo(defaultValue);
            });

    // Test scan with filter on the partitioned default column
    assertThat(table.newScan().filter(Expressions.equal("category", defaultValue)).planFiles())
        .hasSize(2); // All files should match since default applies to all

    // Write new data after schema and partition evolution
    DataFile fileThree = createDataFile("three");
    table.newAppend().appendFile(fileThree).commit();

    // Test that all tasks have access to the column with default value
    assertThat(table.newScan().planFiles())
        .hasSize(3)
        .allSatisfy(
            task -> {
              Schema taskSchema = task.schema();
              Types.NestedField categoryFieldInTask = taskSchema.findField("category");
              assertThat(categoryFieldInTask).isNotNull();
              assertThat(categoryFieldInTask.initialDefault()).isEqualTo(defaultValue);
              assertThat(categoryFieldInTask.writeDefault()).isEqualTo(defaultValue);
            });
  }
}
