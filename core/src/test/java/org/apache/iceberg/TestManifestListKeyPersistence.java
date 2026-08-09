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

import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.iceberg.encryption.EncryptedKey;
import org.apache.iceberg.encryption.EncryptingFileIO;
import org.apache.iceberg.encryption.EncryptionManager;
import org.apache.iceberg.encryption.EncryptionTestHelpers;
import org.apache.iceberg.encryption.EncryptionUtil;
import org.apache.iceberg.encryption.KeyManagementClient;
import org.apache.iceberg.encryption.UnitestKMS;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableMap;
import org.apache.iceberg.relocated.com.google.common.collect.Iterables;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A snapshot with an encrypted manifest list can only be read if the key that encrypts it, and the
 * key encryption key that wraps that key, are in the same table metadata.
 */
class TestManifestListKeyPersistence {

  private static final Map<String, String> TABLE_PROPERTIES =
      ImmutableMap.of(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1);

  @TempDir private Path temp;

  @AfterEach
  public void cleanup() {
    TestTables.clearTables();
  }

  @Test
  void testCommittedSnapshotKeyIsInMetadata() {
    TestTables.TestTable table = createEncryptedTable("mlk-basic");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    Snapshot snapshot = table.currentSnapshot();
    assertThat(snapshot.keyId()).as("manifest list should be encrypted").isNotNull();

    assertThat(keyIds(table.ops().current()))
        .as("committed metadata must contain the snapshot's manifest list key")
        .contains(snapshot.keyId());
  }

  @Test
  void testCommittedSnapshotIsReadableFromCommittedKeys() {
    TestTables.TestTable table = createEncryptedTable("mlk-reload");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    TableMetadata committed = table.ops().current();
    Snapshot snapshot = table.currentSnapshot();

    // what a fresh reader does: build a manager from the committed key records alone
    EncryptionManager reloaded =
        EncryptionUtil.createEncryptionManager(
            committed.encryptionKeys(), TABLE_PROPERTIES, kmsClient());

    assertThat(
            EncryptionUtil.decryptManifestListKeyMetadata(
                new BaseManifestListFile(snapshot.manifestListLocation(), snapshot.keyId()),
                reloaded))
        .isNotNull();
  }

  @Test
  void testStagedSnapshotKeyIsInMetadata() {
    TestTables.TestTable table = createEncryptedTable("mlk-staged");

    table.newFastAppend().appendFile(TestBase.FILE_A).stageOnly().commit();

    Snapshot staged = Iterables.getOnlyElement(table.ops().current().snapshots());
    assertThat(keyIds(table.ops().current())).contains(staged.keyId());
  }

  @Test
  void testTransactionSnapshotKeysAreInMetadata() {
    TestTables.TestTable table = createEncryptedTable("mlk-transaction");

    Transaction transaction = table.newTransaction();
    transaction.newFastAppend().appendFile(TestBase.FILE_A).commit();
    transaction.newFastAppend().appendFile(TestBase.FILE_B).commit();
    transaction.commitTransaction();

    TableMetadata committed = table.ops().current();
    assertThat(committed.snapshots()).hasSize(2);
    for (Snapshot snapshot : committed.snapshots()) {
      assertThat(keyIds(committed)).contains(snapshot.keyId());
    }
  }

  @Test
  void testRetriedCommitPersistsOnlyTheCommittedSnapshotKeys() {
    TestTables.TestTable table = createEncryptedTable("mlk-retry");
    ((TestTables.TestTableOperations) table.ops()).failCommits(2);

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    // three attempts minted three manifest list keys against one shared key encryption key
    Set<String> generated = EncryptionUtil.encryptionKeys(table.ops().encryption()).keySet();
    assertThat(generated).hasSize(4);

    // only the committed attempt's two keys are persisted
    TableMetadata committed = table.ops().current();
    assertThat(keyIds(committed))
        .hasSize(2)
        .contains(table.currentSnapshot().keyId())
        .allMatch(generated::contains);
  }

  private static KeyManagementClient kmsClient() {
    return EncryptionUtil.createKmsClient(
        ImmutableMap.of(
            CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getCanonicalName()));
  }

  private static List<String> keyIds(TableMetadata metadata) {
    return metadata.encryptionKeys().stream().map(EncryptedKey::keyId).collect(Collectors.toList());
  }

  private TestTables.TestTable createEncryptedTable(String name) {
    EncryptionManager encryption = EncryptionTestHelpers.createEncryptionManager();
    File dir = temp.resolve(name).toFile();
    TestTables.TestTableOperations ops =
        new TestTables.TestTableOperations(
            name, dir, EncryptingFileIO.combine(new TestTables.LocalFileIO(), encryption)) {
          @Override
          public EncryptionManager encryption() {
            return encryption;
          }
        };

    return TestTables.create(
        dir, name, TestBase.SCHEMA, TestBase.SPEC, SortOrder.unsorted(), 3, ops);
  }
}
