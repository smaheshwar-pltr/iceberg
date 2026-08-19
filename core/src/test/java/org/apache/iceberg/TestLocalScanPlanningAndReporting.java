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

import java.io.IOException;
import org.apache.iceberg.io.CloseableIterable;
import org.apache.iceberg.metrics.ScanReport;
import org.junit.jupiter.api.TestTemplate;

public class TestLocalScanPlanningAndReporting
    extends ScanPlanningAndReportingTestBase<TableScan, FileScanTask, CombinedScanTask> {

  @Override
  protected TableScan newScan(Table table) {
    return table.newScan();
  }

  @TestTemplate
  void scanSchemaIsNotReportedInMetadata() throws IOException {
    TestMetricsReporter reporter = new TestMetricsReporter();
    Table table =
        TestTables.create(
            tableDir,
            "scan-schema-reporting",
            SCHEMA,
            SPEC,
            SortOrder.unsorted(),
            formatVersion,
            reporter);
    table.newAppend().appendFile(FILE_A).commit();

    TableScan scan =
        table
            .newScan()
            .option(SnapshotScan.USE_SNAPSHOT_SCHEMA, "false")
            .option(SnapshotScan.SCAN_SCHEMA, SchemaParser.toJson(table.schema()))
            .option("reported-option", "reported-value")
            .useSnapshot(table.currentSnapshot().snapshotId());
    try (CloseableIterable<FileScanTask> tasks = scan.planFiles()) {
      tasks.forEach(task -> {});
    }

    ScanReport report = reporter.lastReport();
    assertThat(report.metadata())
        .containsEntry("reported-option", "reported-value")
        .doesNotContainKey(SnapshotScan.SCAN_SCHEMA);
  }
}
