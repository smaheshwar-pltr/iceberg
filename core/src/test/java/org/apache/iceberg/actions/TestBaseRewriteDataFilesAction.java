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
package org.apache.iceberg.actions;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.util.List;
import org.apache.iceberg.CombinedScanTask;
import org.apache.iceberg.DataFile;
import org.apache.iceberg.TestBase;
import org.apache.iceberg.TestTables;
import org.apache.iceberg.expressions.Expressions;
import org.apache.iceberg.io.FileIO;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TestBaseRewriteDataFilesAction {
  @TempDir private File tableDir;

  @AfterEach
  void cleanupTables() {
    TestTables.clearTables();
  }

  @Test
  void currentSnapshotPinUsesCurrentSchema() throws Exception {
    TestTables.TestTable table =
        TestTables.create(tableDir, "test", TestBase.SCHEMA, TestBase.SPEC, 3);
    table.newAppend().appendFile(TestBase.FILE_A).commit();
    table.updateSchema().renameColumn("data", "renamed_data").commit();

    RewriteDataFilesActionResult result =
        new TestRewriteAction(table).filter(Expressions.notNull("renamed_data")).execute();

    assertThat(result.deletedDataFiles()).isEmpty();
    assertThat(result.addedDataFiles()).isEmpty();
  }

  private static class TestRewriteAction extends BaseRewriteDataFilesAction<TestRewriteAction> {
    private TestRewriteAction(TestTables.TestTable table) {
      super(table);
    }

    @Override
    protected FileIO fileIO() {
      return table().io();
    }

    @Override
    protected List<DataFile> rewriteDataForTasks(List<CombinedScanTask> combinedScanTasks) {
      throw new AssertionError("No rewrite should be necessary for a single file");
    }

    @Override
    protected TestRewriteAction self() {
      return this;
    }
  }
}
