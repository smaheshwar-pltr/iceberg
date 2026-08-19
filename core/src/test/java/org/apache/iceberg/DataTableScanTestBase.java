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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.iceberg.expressions.Expressions;
import org.apache.iceberg.io.CloseableIterable;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableList;
import org.apache.iceberg.relocated.com.google.common.collect.Iterables;
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.apache.iceberg.util.CharSequenceMap;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(ParameterizedTestExtension.class)
public abstract class DataTableScanTestBase<
        ScanT extends Scan<ScanT, T, G>, T extends ScanTask, G extends ScanTaskGroup<T>>
    extends ScanTestBase<ScanT, T, G> {

  protected abstract ScanT useRef(ScanT scan, String ref);

  protected abstract ScanT useSnapshot(ScanT scan, long snapshotId);

  protected abstract ScanT asOfTime(ScanT scan, long timestampMillis);

  @TestTemplate
  public void testTaskRowCounts() {
    assumeThat(formatVersion).isEqualTo(2);

    DataFile dataFile1 = newDataFile("data_bucket=0");
    table.newFastAppend().appendFile(dataFile1).commit();

    DataFile dataFile2 = newDataFile("data_bucket=1");
    table.newFastAppend().appendFile(dataFile2).commit();

    DeleteFile deleteFile1 = newDeleteFile("data_bucket=0");
    table.newRowDelta().addDeletes(deleteFile1).commit();

    DeleteFile deleteFile2 = newDeleteFile("data_bucket=1");
    table.newRowDelta().addDeletes(deleteFile2).commit();

    ScanT scan = newScan().option(TableProperties.SPLIT_SIZE, "50");

    List<T> fileScanTasks = Lists.newArrayList(scan.planFiles());
    assertThat(fileScanTasks).as("Must have 2 FileScanTasks").hasSize(2);
    for (T task : fileScanTasks) {
      assertThat(task.estimatedRowsCount()).as("Rows count must match").isEqualTo(10);
    }

    List<G> combinedScanTasks = Lists.newArrayList(scan.planTasks());
    assertThat(combinedScanTasks).as("Must have 4 CombinedScanTask").hasSize(4);
    for (G task : combinedScanTasks) {
      assertThat(task.estimatedRowsCount()).as("Rows count must match").isEqualTo(5);
    }
  }

  protected DataFile newDataFile(String partitionPath) {
    return DataFiles.builder(table.spec())
        .withPath("/path/to/data-" + UUID.randomUUID() + ".parquet")
        .withFormat(FileFormat.PARQUET)
        .withFileSizeInBytes(100)
        .withPartitionPath(partitionPath)
        .withRecordCount(10)
        .build();
  }

  protected DeleteFile newDeleteFile(String partitionPath) {
    return FileMetadata.deleteFileBuilder(table.spec())
        .ofPositionDeletes()
        .withPath("/path/to/delete-" + UUID.randomUUID() + ".parquet")
        .withFormat(FileFormat.PARQUET)
        .withFileSizeInBytes(100)
        .withPartitionPath(partitionPath)
        .withRecordCount(10)
        .build();
  }

  @TestTemplate
  public void testScanFromBranchTip() throws IOException {
    table.newFastAppend().appendFile(FILE_A).commit();
    // Add B and C to new branch
    table.newFastAppend().appendFile(FILE_B).appendFile(FILE_C).toBranch("testBranch").commit();
    // Add D to main
    table.newFastAppend().appendFile(FILE_D).commit();

    ScanT testBranchScan = useRef(newScan(), "testBranch");
    validateExpectedFileScanTasks(
        testBranchScan, ImmutableList.of(FILE_A.location(), FILE_B.location(), FILE_C.location()));

    ScanT mainScan = newScan();
    validateExpectedFileScanTasks(mainScan, ImmutableList.of(FILE_A.location(), FILE_D.location()));
  }

  @TestTemplate
  public void testScanFromTag() throws IOException {
    table.newFastAppend().appendFile(FILE_A).appendFile(FILE_B).commit();
    table.manageSnapshots().createTag("tagB", table.currentSnapshot().snapshotId()).commit();
    table.newFastAppend().appendFile(FILE_C).commit();
    ScanT tagScan = useRef(newScan(), "tagB");
    validateExpectedFileScanTasks(tagScan, ImmutableList.of(FILE_A.location(), FILE_B.location()));
    ScanT mainScan = newScan();
    validateExpectedFileScanTasks(
        mainScan, ImmutableList.of(FILE_A.location(), FILE_B.location(), FILE_C.location()));
  }

  @TestTemplate
  public void testScanFromRefWhenSnapshotSetFails() {
    table.newFastAppend().appendFile(FILE_A).appendFile(FILE_B).commit();
    table.manageSnapshots().createTag("tagB", table.currentSnapshot().snapshotId()).commit();

    assertThatThrownBy(
            () -> useRef(useSnapshot(newScan(), table.currentSnapshot().snapshotId()), "tagB"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot override ref, already set snapshot id=1");
  }

  @TestTemplate
  public void testSettingSnapshotWhenRefSetFails() {
    table.newFastAppend().appendFile(FILE_A).commit();
    Snapshot snapshotA = table.currentSnapshot();
    table.newFastAppend().appendFile(FILE_B).commit();
    table.manageSnapshots().createTag("tagB", table.currentSnapshot().snapshotId()).commit();

    assertThatThrownBy(() -> useSnapshot(useRef(newScan(), "tagB"), snapshotA.snapshotId()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot override snapshot, already set snapshot id=2");
  }

  @TestTemplate
  public void testBranchTimeTravelFails() {
    table.newFastAppend().appendFile(FILE_A).appendFile(FILE_B).commit();
    table
        .manageSnapshots()
        .createBranch("testBranch", table.currentSnapshot().snapshotId())
        .commit();

    assertThatThrownBy(() -> asOfTime(useRef(newScan(), "testBranch"), System.currentTimeMillis()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot override snapshot, already set snapshot id=1");
  }

  @TestTemplate
  public void testSettingMultipleRefsFails() {
    table.newFastAppend().appendFile(FILE_A).commit();
    table.manageSnapshots().createTag("tagA", table.currentSnapshot().snapshotId()).commit();
    table.newFastAppend().appendFile(FILE_B).commit();
    table.manageSnapshots().createTag("tagB", table.currentSnapshot().snapshotId()).commit();

    assertThatThrownBy(() -> useRef(useRef(newScan(), "tagB"), "tagA"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot override ref, already set snapshot id=2");
  }

  @TestTemplate
  public void testSettingInvalidRefFails() {
    assertThatThrownBy(() -> useRef(newScan(), "nonexisting"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot find ref nonexisting");
  }

  @TestTemplate
  public void exactSnapshotPinPlansWithCurrentSchema() throws IOException {
    table.newFastAppend().appendFile(FILE_A).commit();
    long snapshotId = table.currentSnapshot().snapshotId();

    table.updateSchema().renameColumn("data", "renamed_data").commit();

    ScanT scan =
        useSnapshot(newScan().option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"), snapshotId)
            .filter(Expressions.notNull("renamed_data"));
    assertThat(scan.schema()).isEqualTo(table.schema());
    validateExpectedFileScanTasks(scan, ImmutableList.of(FILE_A.location()));
  }

  @TestTemplate
  public void exactSnapshotPinRemainsOnCapturedSnapshot() throws IOException {
    table.newFastAppend().appendFile(FILE_A).commit();
    long snapshotId = table.currentSnapshot().snapshotId();
    ScanT scan =
        useSnapshot(newScan().option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"), snapshotId);

    table.newFastAppend().appendFile(FILE_B).commit();

    validateExpectedFileScanTasks(scan, ImmutableList.of(FILE_A.location()));
  }

  @TestTemplate
  public void exactSnapshotPinRetainsSchemaAfterTableSchemaChange() throws IOException {
    table.newFastAppend().appendFile(FILE_A).commit();
    long snapshotId = table.currentSnapshot().snapshotId();
    Schema pinnedSchema = table.schema();
    ScanT scan =
        useSnapshot(newScan().option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"), snapshotId)
            .filter(Expressions.notNull("data"));

    table.updateSchema().renameColumn("data", "renamed_data").commit();

    assertThat(scan.schema()).isEqualTo(pinnedSchema);
    validateExpectedFileScanTasks(scan, ImmutableList.of(FILE_A.location()));
  }

  @TestTemplate
  public void exactSnapshotPinUsesCapturedScanSchemaInEitherOptionOrder() throws IOException {
    table.newFastAppend().appendFile(FILE_A).commit();
    long snapshotId = table.currentSnapshot().snapshotId();
    table.updateSchema().renameColumn("data", "captured_data").commit();
    Schema capturedSchema = table.schema();
    String capturedSchemaJson = SchemaParser.toJson(capturedSchema);
    table.updateSchema().renameColumn("captured_data", "latest_data").commit();

    ScanT schemaFirst =
        useSnapshot(
                newScan()
                    .option(SnapshotScan.SCAN_SCHEMA, capturedSchemaJson)
                    .option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"),
                snapshotId)
            .filter(Expressions.notNull("captured_data"));
    ScanT selectionFirst =
        useSnapshot(
                newScan()
                    .option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false")
                    .option(SnapshotScan.SCAN_SCHEMA, capturedSchemaJson),
                snapshotId)
            .filter(Expressions.notNull("captured_data"));

    assertThat(schemaFirst.schema()).isEqualTo(capturedSchema);
    assertThat(selectionFirst.schema()).isEqualTo(capturedSchema);
    validateExpectedFileScanTasks(schemaFirst, ImmutableList.of(FILE_A.location()));
    validateExpectedFileScanTasks(selectionFirst, ImmutableList.of(FILE_A.location()));
  }

  @TestTemplate
  public void exactSnapshotScanSchemaRequiresCurrentSchemaSelection() {
    table.newFastAppend().appendFile(FILE_A).commit();
    long snapshotId = table.currentSnapshot().snapshotId();
    String schemaJson = SchemaParser.toJson(table.schema());

    assertThatThrownBy(
            () -> useSnapshot(newScan().option(SnapshotScan.SCAN_SCHEMA, schemaJson), snapshotId))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(
            "Cannot use scan option scan-schema unless scan option use-snapshot-schema is false");
  }

  @TestTemplate
  public void exactSnapshotScanSchemaRequiresSchemaId() {
    table.newFastAppend().appendFile(FILE_A).commit();
    long snapshotId = table.currentSnapshot().snapshotId();

    assertThatThrownBy(
            () ->
                useSnapshot(
                    newScan()
                        .option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false")
                        .option(SnapshotScan.SCAN_SCHEMA, "{\"type\":\"struct\",\"fields\":[]}"),
                    snapshotId))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid scan schema: missing schema-id");
  }

  @TestTemplate
  public void exactSnapshotSchemaOptionRejectsInvalidValue() {
    assertThatThrownBy(() -> newScan().option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "invalid"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(
            "Invalid value for scan option use-snapshot-schema: invalid (must be true or false)");
  }

  @TestTemplate
  public void exactSnapshotSchemaOptionMustPrecedeSnapshot() {
    table.newFastAppend().appendFile(FILE_A).commit();
    ScanT scan = useSnapshot(newScan(), table.currentSnapshot().snapshotId());

    assertThatThrownBy(() -> scan.option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot set scan option use-snapshot-schema, snapshot already set to id=1");
    assertThatThrownBy(
            () -> scan.option(SnapshotScan.SCAN_SCHEMA, SchemaParser.toJson(table.schema())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot set scan option scan-schema, snapshot already set to id=1");
  }

  @TestTemplate
  public void exactSnapshotSchemaOptionCannotBeUsedWithRef() {
    table.newFastAppend().appendFile(FILE_A).commit();
    table.manageSnapshots().createBranch("branch", table.currentSnapshot().snapshotId()).commit();

    assertThatThrownBy(
            () -> useRef(newScan().option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"), "branch"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot use non-main ref when scan option use-snapshot-schema is set");
    assertThatThrownBy(
            () -> useRef(newScan(), "branch").option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot set scan option use-snapshot-schema, snapshot already set to id=1");
    assertThatThrownBy(
            () ->
                useRef(
                    newScan().option(SnapshotScan.SCAN_SCHEMA, SchemaParser.toJson(table.schema())),
                    "branch"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot use non-main ref when scan option scan-schema is set");
  }

  @TestTemplate
  public void exactSnapshotSchemaOptionCannotBeUsedWithTimestamp() {
    table.newFastAppend().appendFile(FILE_A).commit();

    assertThatThrownBy(
            () ->
                asOfTime(
                    newScan().option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"),
                    System.currentTimeMillis()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot use timestamp when scan option use-snapshot-schema is set");
    assertThatThrownBy(
            () ->
                asOfTime(
                    newScan().option(SnapshotScan.SCAN_SCHEMA, SchemaParser.toJson(table.schema())),
                    System.currentTimeMillis()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot use timestamp when scan option scan-schema is set");
  }

  @TestTemplate
  public void mainRefCanBeCombinedWithExactSnapshotSchemaOption() throws IOException {
    table.newFastAppend().appendFile(FILE_A).commit();
    long snapshotId = table.currentSnapshot().snapshotId();

    ScanT optionBeforeRef =
        useSnapshot(
            useRef(
                newScan().option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"),
                SnapshotRef.MAIN_BRANCH),
            snapshotId);
    ScanT refBeforeOption =
        useSnapshot(
            useRef(newScan(), SnapshotRef.MAIN_BRANCH)
                .option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false"),
            snapshotId);

    validateExpectedFileScanTasks(optionBeforeRef, ImmutableList.of(FILE_A.location()));
    validateExpectedFileScanTasks(refBeforeOption, ImmutableList.of(FILE_A.location()));
  }

  private void validateExpectedFileScanTasks(ScanT scan, List<CharSequence> expectedFileScanPaths)
      throws IOException {
    validateExpectedFileScanTasks(scan, expectedFileScanPaths, null);
  }

  private void validateExpectedFileScanTasks(
      ScanT scan,
      Collection<CharSequence> expectedFileScanPaths,
      CharSequenceMap<String> fileToManifest)
      throws IOException {
    try (CloseableIterable<T> scanTasks = scan.planFiles()) {
      assertThat(scanTasks).hasSameSizeAs(expectedFileScanPaths);
      List<CharSequence> actualFiles = Lists.newArrayList();
      for (T task : scanTasks) {
        DataFile dataFile = ((FileScanTask) task).file();
        actualFiles.add(dataFile.location());
        if (fileToManifest != null) {
          assertThat(fileToManifest.get(dataFile.location()))
              .isEqualTo(dataFile.manifestLocation());
        }
      }

      assertThat(actualFiles).containsAll(expectedFileScanPaths);
    }
  }

  @TestTemplate
  public void testSequenceNumbersThroughPlanFiles() {
    assumeThat(formatVersion).isEqualTo(2);

    DataFile dataFile1 = newDataFile("data_bucket=0");
    table.newFastAppend().appendFile(dataFile1).commit();

    DataFile dataFile2 = newDataFile("data_bucket=1");
    table.newFastAppend().appendFile(dataFile2).commit();

    DeleteFile deleteFile1 = newDeleteFile("data_bucket=0");
    table.newRowDelta().addDeletes(deleteFile1).commit();

    DeleteFile deleteFile2 = newDeleteFile("data_bucket=1");
    table.newRowDelta().addDeletes(deleteFile2).commit();

    ScanT scan = newScan();

    List<T> fileScanTasks = Lists.newArrayList(scan.planFiles());
    assertThat(fileScanTasks).as("Must have 2 FileScanTasks").hasSize(2);
    for (T task : fileScanTasks) {
      FileScanTask fileScanTask = (FileScanTask) task;
      DataFile file = fileScanTask.file();
      long expectedDataSequenceNumber = 0L;
      long expectedDeleteSequenceNumber = 0L;
      if (file.location().equals(dataFile1.location())) {
        expectedDataSequenceNumber = 1L;
        expectedDeleteSequenceNumber = 3L;
      }

      if (file.location().equals(dataFile2.location())) {
        expectedDataSequenceNumber = 2L;
        expectedDeleteSequenceNumber = 4L;
      }

      assertThat(file.dataSequenceNumber().longValue())
          .as("Data sequence number mismatch")
          .isEqualTo(expectedDataSequenceNumber);

      assertThat(file.fileSequenceNumber().longValue())
          .as("File sequence number mismatch")
          .isEqualTo(expectedDataSequenceNumber);

      List<DeleteFile> deleteFiles = fileScanTask.deletes();
      assertThat(deleteFiles).as("Must have 1 delete file").hasSize(1);

      DeleteFile deleteFile = Iterables.getOnlyElement(deleteFiles);
      assertThat(deleteFile.dataSequenceNumber().longValue())
          .as("Data sequence number mismatch")
          .isEqualTo(expectedDeleteSequenceNumber);

      assertThat(deleteFile.fileSequenceNumber().longValue())
          .as("File sequence number mismatch")
          .isEqualTo(expectedDeleteSequenceNumber);
    }
  }

  @TestTemplate
  public void testManifestLocationsInScan() throws IOException {
    table.newFastAppend().appendFile(FILE_A).commit();
    ManifestFile firstDataManifest = table.currentSnapshot().allManifests(table.io()).get(0);
    table.newFastAppend().appendFile(FILE_B).appendFile(FILE_C).commit();
    ManifestFile secondDataManifest =
        table.currentSnapshot().dataManifests(table.io()).stream()
            .filter(manifest -> manifest.snapshotId() == table.currentSnapshot().snapshotId())
            .collect(Collectors.toList())
            .get(0);
    CharSequenceMap<String> fileToManifest = CharSequenceMap.create();
    fileToManifest.put(FILE_A.location(), firstDataManifest.path());
    fileToManifest.put(FILE_B.location(), secondDataManifest.path());
    fileToManifest.put(FILE_C.location(), secondDataManifest.path());

    validateExpectedFileScanTasks(newScan(), fileToManifest.keySet(), fileToManifest);
  }

  @TestTemplate
  public void testManifestLocationsInScanWithDeleteFiles() throws IOException {
    assumeThat(formatVersion).isEqualTo(2);

    table.newFastAppend().appendFile(FILE_A).commit();
    ManifestFile firstManifest = table.currentSnapshot().allManifests(table.io()).get(0);
    DeleteFile deleteFile = newDeleteFile("data_bucket=0");
    table.newRowDelta().addDeletes(deleteFile).commit();
    CharSequenceMap<String> fileToManifest = CharSequenceMap.create();
    fileToManifest.put(FILE_A.location(), firstManifest.path());
    ScanT scan = newScan();
    validateExpectedFileScanTasks(scan, ImmutableList.of(FILE_A.location()), fileToManifest);
    List<DeleteFile> deletes = Lists.newArrayList();
    try (CloseableIterable<T> scanTasks = scan.planFiles()) {
      for (T task : scanTasks) {
        FileScanTask fileScanTask = (FileScanTask) task;
        deletes.addAll(fileScanTask.deletes());
      }
    }

    assertThat(deletes).hasSize(1);
    ManifestFile deleteManifest =
        table.currentSnapshot().deleteManifests(table.io()).stream()
            .filter(manifest -> manifest.snapshotId() == table.currentSnapshot().snapshotId())
            .collect(Collectors.toList())
            .get(0);
    assertThat(deletes.get(0).manifestLocation()).isEqualTo(deleteManifest.path());
  }
}
