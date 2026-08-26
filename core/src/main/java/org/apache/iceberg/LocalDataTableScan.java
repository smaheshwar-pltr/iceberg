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

import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.util.SnapshotUtil;

class LocalDataTableScan extends DataTableScan {
  private final boolean exactSnapshot;

  LocalDataTableScan(Table table, Schema schema, TableScanContext context) {
    this(table, schema, context, false);
  }

  private LocalDataTableScan(
      Table table, Schema schema, TableScanContext context, boolean exactSnapshot) {
    super(table, schema, context);
    this.exactSnapshot = exactSnapshot;
  }

  @Override
  public TableScan atSnapshot(long snapshotId) {
    Snapshot snapshot = validateSnapshotSelection(snapshotId);
    Preconditions.checkArgument(
        snapshot.schemaId() != null, "Cannot determine schema for snapshot with ID %s", snapshotId);
    return new LocalDataTableScan(
        table(),
        SnapshotUtil.schemaFor(table(), snapshotId),
        context().useSnapshotId(snapshotId),
        true);
  }

  @Override
  boolean bindSpecsToScanSchema() {
    return exactSnapshot;
  }

  @Override
  protected TableScan newRefinedScan(Table table, Schema schema, TableScanContext context) {
    return new LocalDataTableScan(table, schema, context, exactSnapshot);
  }
}
