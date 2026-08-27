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
package org.apache.iceberg.spark.source;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.iceberg.ParameterizedTestExtension;
import org.apache.iceberg.Table;
import org.apache.iceberg.spark.CatalogTestBase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Spark reads a main table by pinning the current snapshot, whether or not the query is time
 * travel. A pin must keep resolving names in the table's schema; only an explicit {@code VERSION AS
 * OF} or {@code TIMESTAMP AS OF} should resolve them in the snapshot's schema.
 *
 * <p>These are the two halves of that distinction. They are gates rather than coverage: if the pin
 * ever selects the snapshot schema, {@link #filterOnColumnAddedWithoutASnapshot} fails, and nothing
 * else in the tree catches it.
 */
@ExtendWith(ParameterizedTestExtension.class)
public class TestSnapshotBindingSchema extends CatalogTestBase {

  @AfterEach
  public void dropTestTable() {
    sql("DROP TABLE IF EXISTS %s", tableName);
  }

  @TestTemplate
  public void filterOnColumnAddedWithoutASnapshot() {
    sql("CREATE TABLE %s (id bigint, data string) USING iceberg", tableName);
    sql("INSERT INTO %s VALUES (1, 'a'), (2, 'b')", tableName);

    // a schema-only change: it creates no snapshot, so the snapshot Spark pins does not record it
    sql("ALTER TABLE %s ADD COLUMN extra int", tableName);

    // the pin freezes the file set. Spark projected the current schema and pushes a filter written
    // against it, so "extra" must still resolve.
    assertThat(sql("SELECT * FROM %s WHERE extra IS NULL", tableName)).hasSize(2);
    assertThat(sql("SELECT * FROM %s WHERE extra = 1", tableName)).isEmpty();

    // a projection of the new column resolves too
    assertThat(sql("SELECT extra FROM %s", tableName)).hasSize(2);
  }

  @TestTemplate
  public void filterOnColumnDroppedWithoutASnapshot() {
    sql("CREATE TABLE %s (id bigint, data string) USING iceberg", tableName);
    sql("INSERT INTO %s VALUES (1, 'a'), (2, 'b')", tableName);

    Table table = validationCatalog.loadTable(tableIdent);
    long snapshotId = table.currentSnapshot().snapshotId();

    // a schema-only change, so the snapshot below is still the current snapshot
    sql("ALTER TABLE %s DROP COLUMN data", tableName);

    // an explicit time-travel read resolves names in the snapshot's schema, which still has "data".
    // Before binding schemas were explicit this threw, and started working again as soon as an
    // unrelated writer committed.
    assertThat(sql("SELECT * FROM %s VERSION AS OF %d WHERE data = 'a'", tableName, snapshotId))
        .hasSize(1);

    // an unrelated commit must not change the answer
    sql("INSERT INTO %s VALUES (3)", tableName);
    assertThat(sql("SELECT * FROM %s VERSION AS OF %d WHERE data = 'a'", tableName, snapshotId))
        .hasSize(1);
  }
}
