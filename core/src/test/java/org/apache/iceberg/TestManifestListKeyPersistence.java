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
 * Verifies the metadata updates produced by {@link SnapshotProducer} with a test-injected standard
 * encryption manager. Hive integration coverage verifies the supported catalog path.
 */
class TestManifestListKeyPersistence {
  private static final Map<String, String> TABLE_PROPERTIES =
      ImmutableMap.of(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1);

  @TempDir private Path temp;

  @AfterEach
  void cleanup() {
    TestTables.clearTables();
  }

  @Test
  void committedSnapshotIncludesReadableManifestListKeys() {
    TestTables.TestTable table = createEncryptedTable("mlk-basic");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    TableMetadata committed = table.ops().current();
    Snapshot snapshot = table.currentSnapshot();
    assertSnapshotKeysCommitted(committed, snapshot);
    assertReadableFromCommittedKeys(committed, snapshot);
  }

  @Test
  void stagedSnapshotIncludesManifestListKeys() {
    TestTables.TestTable table = createEncryptedTable("mlk-staged");

    table.newFastAppend().appendFile(TestBase.FILE_A).stageOnly().commit();

    TableMetadata committed = table.ops().current();
    Snapshot staged = Iterables.getOnlyElement(committed.snapshots());
    assertSnapshotKeysCommitted(committed, staged);
    assertReadableFromCommittedKeys(committed, staged);
  }

  @Test
  void retriedCommitPersistsOnlySuccessfulAttemptKeys() {
    TestTables.TestTable table = createEncryptedTable("mlk-retry");
    ((TestTables.TestTableOperations) table.ops()).failCommits(2);

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    TableMetadata committed = table.ops().current();
    Snapshot snapshot = table.currentSnapshot();
    EncryptedKey manifestListKey = key(committed, snapshot.keyId());

    assertThat(manifestListKey).isNotNull();
    assertThat(keyIds(committed))
        .containsExactlyInAnyOrder(snapshot.keyId(), manifestListKey.encryptedById());
    assertReadableFromCommittedKeys(committed, snapshot);
  }

  private static KeyManagementClient kmsClient() {
    return EncryptionUtil.createKmsClient(
        ImmutableMap.of(
            CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getCanonicalName()));
  }

  private static List<String> keyIds(TableMetadata metadata) {
    return metadata.encryptionKeys().stream().map(EncryptedKey::keyId).collect(Collectors.toList());
  }

  private static EncryptedKey key(TableMetadata metadata, String keyId) {
    return metadata.encryptionKeys().stream()
        .filter(key -> key.keyId().equals(keyId))
        .findFirst()
        .orElse(null);
  }

  private static void assertSnapshotKeysCommitted(TableMetadata metadata, Snapshot snapshot) {
    assertThat(snapshot.keyId()).as("manifest list key ID").isNotNull();
    EncryptedKey manifestListKey = key(metadata, snapshot.keyId());
    assertThat(manifestListKey).as("manifest list key").isNotNull();
    assertThat(keyIds(metadata))
        .as("manifest list key and wrapping key")
        .contains(snapshot.keyId(), manifestListKey.encryptedById());
  }

  private static void assertReadableFromCommittedKeys(TableMetadata metadata, Snapshot snapshot) {
    EncryptionManager reloaded =
        EncryptionUtil.createEncryptionManager(
            metadata.encryptionKeys(), TABLE_PROPERTIES, kmsClient());
    EncryptingFileIO reloadedIO = EncryptingFileIO.combine(new TestTables.LocalFileIO(), reloaded);

    assertThat(snapshot.allManifests(reloadedIO)).isNotEmpty();
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
