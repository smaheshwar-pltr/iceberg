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
import org.apache.iceberg.io.FileIO;
import org.apache.iceberg.io.LocationProvider;
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
  void cleanup() {
    TestTables.clearTables();
  }

  @Test
  void committedSnapshotKeyIsInMetadata() {
    TestTables.TestTable table = createEncryptedTable("mlk-basic");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    TableMetadata committed = table.ops().current();
    Snapshot snapshot = table.currentSnapshot();
    assertThat(snapshot.keyId()).as("manifest list should be encrypted").isNotNull();

    EncryptedKey manifestListKey = key(committed, snapshot.keyId());
    assertThat(manifestListKey).isNotNull();
    assertThat(keyIds(committed))
        .as("committed metadata must contain the snapshot's manifest list key")
        .contains(snapshot.keyId(), manifestListKey.encryptedById());
  }

  @Test
  void committedSnapshotIsReadableFromCommittedKeys() {
    TestTables.TestTable table = createEncryptedTable("mlk-reload");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    TableMetadata committed = table.ops().current();
    assertReadableFromCommittedKeys(committed, table.currentSnapshot());
  }

  @Test
  void stagedSnapshotKeyIsInMetadata() {
    TestTables.TestTable table = createEncryptedTable("mlk-staged");

    table.newFastAppend().appendFile(TestBase.FILE_A).stageOnly().commit();

    Snapshot staged = Iterables.getOnlyElement(table.ops().current().snapshots());
    assertThat(keyIds(table.ops().current())).contains(staged.keyId());
  }

  @Test
  void transactionSnapshotKeysAreInMetadata() {
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
  void retriedCommitPersistsReadableSnapshotKeys() {
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

  @Test
  void transactionRebaseUsesKeysFromRefreshedMetadata() {
    TestTables.TestTable table = createMetadataScopedEncryptedTable("mlk-rebase");
    Transaction transaction = table.newTransaction();
    transaction.newFastAppend().appendFile(TestBase.FILE_A).commit();

    table.newFastAppend().appendFile(TestBase.FILE_B).commit();
    transaction.commitTransaction();

    TableMetadata committed = table.ops().current();
    assertThat(committed.snapshots()).hasSize(2);
    assertReadableFromCommittedKeys(committed, committed.currentSnapshot());
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

  private static void assertReadableFromCommittedKeys(TableMetadata committed, Snapshot snapshot) {
    EncryptionManager reloaded =
        EncryptionUtil.createEncryptionManager(
            committed.encryptionKeys(), TABLE_PROPERTIES, kmsClient());
    EncryptingFileIO reloadedIO = EncryptingFileIO.combine(new TestTables.LocalFileIO(), reloaded);

    assertThat(snapshot.allManifests(reloadedIO)).isNotEmpty();
  }

  private TestTables.TestTable createEncryptedTable(String name) {
    return createEncryptedTable(name, false);
  }

  private TestTables.TestTable createMetadataScopedEncryptedTable(String name) {
    return createEncryptedTable(name, true);
  }

  private TestTables.TestTable createEncryptedTable(String name, boolean useMetadataScopedTemp) {
    EncryptionManager encryption = EncryptionTestHelpers.createEncryptionManager();
    File dir = temp.resolve(name).toFile();
    FileIO plainFileIO = new TestTables.LocalFileIO();
    TestTables.TestTableOperations ops =
        new TestTables.TestTableOperations(
            name, dir, EncryptingFileIO.combine(plainFileIO, encryption)) {
          @Override
          public EncryptionManager encryption() {
            return encryption;
          }

          @Override
          public TableOperations temp(TableMetadata uncommittedMetadata) {
            return useMetadataScopedTemp
                ? metadataScopedTemp(this, uncommittedMetadata, plainFileIO)
                : this;
          }
        };

    return TestTables.create(
        dir, name, TestBase.SCHEMA, TestBase.SPEC, SortOrder.unsorted(), 3, ops);
  }

  private static TableOperations metadataScopedTemp(
      TableOperations outer, TableMetadata metadata, FileIO plainFileIO) {
    EncryptionManager encryption =
        EncryptionUtil.createEncryptionManager(
            metadata.encryptionKeys(), TABLE_PROPERTIES, kmsClient());
    FileIO encryptedFileIO = EncryptingFileIO.combine(plainFileIO, encryption);

    return new TableOperations() {
      @Override
      public TableMetadata current() {
        return metadata;
      }

      @Override
      public TableMetadata refresh() {
        throw new UnsupportedOperationException("Cannot refresh temporary table operations");
      }

      @Override
      public void commit(TableMetadata base, TableMetadata updated) {
        throw new UnsupportedOperationException("Cannot commit temporary table operations");
      }

      @Override
      public FileIO io() {
        return encryptedFileIO;
      }

      @Override
      public EncryptionManager encryption() {
        return encryption;
      }

      @Override
      public String metadataFileLocation(String fileName) {
        return outer.metadataFileLocation(fileName);
      }

      @Override
      public LocationProvider locationProvider() {
        return LocationProviders.locationsFor(metadata.location(), metadata.properties());
      }

      @Override
      public long newSnapshotId() {
        return outer.newSnapshotId();
      }
    };
  }
}
