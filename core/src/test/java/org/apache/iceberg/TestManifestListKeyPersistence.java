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
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies that a snapshot referencing an encrypted manifest list is only ever committed in the
 * same metadata update that adds the manifest list key and the key encryption key wrapping it.
 *
 * <p>Tables in this class are backed by operations that rebuild their encryption manager from
 * committed metadata after every commit, discarding the manager that minted the keys. This is what
 * a catalog does on refresh, so a manifest list is readable here only if the keys it needs were
 * committed with its snapshot.
 */
public class TestManifestListKeyPersistence {

  private static final Map<String, String> TABLE_PROPERTIES =
      ImmutableMap.of(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1);

  @TempDir private Path temp;

  /** Metadata updates of the most recent commit, captured before the table discards them. */
  private List<MetadataUpdate> committedChanges = List.of();

  @AfterEach
  public void cleanup() {
    TestTables.clearTables();
  }

  @Test
  public void testCommittedKeysReadManifestList() {
    TestTables.TestTable table = createEncryptedTable("committed");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    Snapshot snapshot = table.currentSnapshot();
    assertThat(snapshot.keyId()).as("snapshot should reference a manifest list key").isNotNull();
    assertManifestListReadable(table.ops().current(), snapshot);
  }

  @Test
  public void testKeysAreAddedBeforeTheSnapshotThatUsesThem() {
    TestTables.TestTable table = createEncryptedTable("ordering");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    assertThat(committedChanges)
        .extracting(Object::getClass)
        .containsExactly(
            MetadataUpdate.AddEncryptionKey.class,
            MetadataUpdate.AddEncryptionKey.class,
            MetadataUpdate.AddSnapshot.class,
            MetadataUpdate.SetSnapshotRef.class);

    EncryptedKey keyEncryptionKey = addedKey(0);
    EncryptedKey manifestListKey = addedKey(1);
    Snapshot added = ((MetadataUpdate.AddSnapshot) committedChanges.get(2)).snapshot();

    assertThat(manifestListKey.keyId())
        .as("second key should be the manifest list key the snapshot references")
        .isEqualTo(added.keyId());
    assertThat(manifestListKey.encryptedById())
        .as("manifest list key should be wrapped by the key added before it")
        .isEqualTo(keyEncryptionKey.keyId());
  }

  @Test
  public void testStagedSnapshotKeysArePersisted() {
    TestTables.TestTable table = createEncryptedTable("staged");

    table.newFastAppend().appendFile(TestBase.FILE_A).stageOnly().commit();

    TableMetadata metadata = table.ops().current();
    assertThat(metadata.refs())
        .as("staged snapshot should not be on any branch")
        .doesNotContainKey(SnapshotRef.MAIN_BRANCH);
    assertThat(metadata.snapshots()).hasSize(1);
    assertManifestListReadable(metadata, metadata.snapshots().get(0));
  }

  @Test
  public void testRetryPersistsOnlyTheSuccessfulAttemptKeys() {
    TestTables.TestTable table = createEncryptedTable("retry");
    ((TestTables.TestTableOperations) table.ops()).failCommits(2);

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    TableMetadata metadata = table.ops().current();
    Snapshot snapshot = table.currentSnapshot();
    String keyEncryptionKeyId = findKey(metadata, snapshot.keyId()).encryptedById();

    assertThat(keyIds(metadata))
        .as("abandoned attempts should not leave their keys behind")
        .containsExactlyInAnyOrder(snapshot.keyId(), keyEncryptionKeyId);
    assertManifestListReadable(metadata, snapshot);
  }

  @Test
  public void testCherryPickFastForwardAddsNoKeys() {
    TestTables.TestTable table = createEncryptedTable("cherry-pick");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();
    // a staged snapshot whose parent is the current snapshot can be fast-forwarded onto the branch
    table.newFastAppend().appendFile(TestBase.FILE_B).stageOnly().commit();

    long stagedSnapshotId =
        table.ops().current().snapshots().stream()
            .map(Snapshot::snapshotId)
            .filter(id -> id != table.currentSnapshot().snapshotId())
            .findFirst()
            .orElseThrow();
    List<String> keyIdsBeforeCherryPick = keyIds(table.ops().current());

    table.manageSnapshots().cherrypick(stagedSnapshotId).commit();

    assertThat(table.currentSnapshot().snapshotId())
        .as("cherry-pick should have fast-forwarded to the staged snapshot")
        .isEqualTo(stagedSnapshotId);
    assertThat(keyIds(table.ops().current()))
        .as("installing a snapshot already in metadata should add no keys")
        .isEqualTo(keyIdsBeforeCherryPick);
    assertThat(committedChanges)
        .as("fast-forward should not emit AddEncryptionKey")
        .noneMatch(MetadataUpdate.AddEncryptionKey.class::isInstance);
    assertManifestListReadable(table.ops().current(), table.currentSnapshot());
  }

  /**
   * Asserts that a manifest list is readable using only the keys present in the given metadata, by
   * building an encryption manager the way a catalog does on refresh.
   */
  private static void assertManifestListReadable(TableMetadata metadata, Snapshot snapshot) {
    EncryptedKey manifestListKey = findKey(metadata, snapshot.keyId());
    assertThat(manifestListKey)
        .as("committed metadata should contain manifest list key %s", snapshot.keyId())
        .isNotNull();
    assertThat(findKey(metadata, manifestListKey.encryptedById()))
        .as(
            "committed metadata should contain key encryption key %s",
            manifestListKey.encryptedById())
        .isNotNull();

    FileIO io = EncryptingFileIO.combine(new TestTables.LocalFileIO(), encryptionManager(metadata));
    assertThat(snapshot.allManifests(io))
        .as("manifest list should be readable from committed keys alone")
        .isNotEmpty();
  }

  /**
   * Creates an encrypted table whose operations rebuild the encryption manager from committed
   * metadata after every commit, so keys that were not committed become unreachable.
   */
  private TestTables.TestTable createEncryptedTable(String name) {
    EncryptionManager initialEncryption = EncryptionTestHelpers.createEncryptionManager();
    File dir = temp.resolve(name).toFile();
    FileIO plainFileIO = new TestTables.LocalFileIO();

    TestTables.TestTableOperations ops =
        new TestTables.TestTableOperations(
            name, dir, EncryptingFileIO.combine(plainFileIO, initialEncryption)) {
          private EncryptionManager encryption = initialEncryption;
          private FileIO io = EncryptingFileIO.combine(plainFileIO, initialEncryption);

          @Override
          public EncryptionManager encryption() {
            return encryption;
          }

          @Override
          public FileIO io() {
            return io;
          }

          @Override
          public void commit(TableMetadata base, TableMetadata metadata) {
            committedChanges = List.copyOf(metadata.changes());
            super.commit(base, metadata);
            this.encryption = encryptionManager(current());
            this.io = EncryptingFileIO.combine(plainFileIO, encryption);
          }
        };

    return TestTables.create(
        dir, name, TestBase.SCHEMA, TestBase.SPEC, SortOrder.unsorted(), 3, ops);
  }

  private EncryptedKey addedKey(int index) {
    return ((MetadataUpdate.AddEncryptionKey) committedChanges.get(index)).key();
  }

  private static EncryptionManager encryptionManager(TableMetadata metadata) {
    return EncryptionUtil.createEncryptionManager(
        metadata.encryptionKeys(), TABLE_PROPERTIES, kmsClient());
  }

  private static KeyManagementClient kmsClient() {
    return EncryptionUtil.createKmsClient(
        ImmutableMap.of(
            CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getCanonicalName()));
  }

  private static EncryptedKey findKey(TableMetadata metadata, String keyId) {
    return metadata.encryptionKeys().stream()
        .filter(key -> key.keyId().equals(keyId))
        .findFirst()
        .orElse(null);
  }

  private static List<String> keyIds(TableMetadata metadata) {
    return metadata.encryptionKeys().stream().map(EncryptedKey::keyId).collect(Collectors.toList());
  }
}
