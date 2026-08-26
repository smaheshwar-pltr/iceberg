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
import org.apache.iceberg.rest.requests.UpdateTableRequest;
import org.apache.iceberg.rest.requests.UpdateTableRequestParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TestManifestListKeyPersistence {
  private static final Map<String, String> TABLE_PROPERTIES =
      ImmutableMap.of(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1);

  @TempDir private Path temp;
  private List<MetadataUpdate> committedChanges = List.of();

  @AfterEach
  void cleanup() {
    TestTables.clearTables();
  }

  @Test
  void stageOnlyAddsKeysBeforeSnapshotWithoutUpdatingRef() {
    TestTables.TestTable table = createEncryptedTable("stage-only");

    table.newFastAppend().appendFile(TestBase.FILE_A).stageOnly().commit();

    assertThat(committedChanges)
        .extracting(Object::getClass)
        .containsExactly(
            MetadataUpdate.AddEncryptionKey.class,
            MetadataUpdate.AddEncryptionKey.class,
            MetadataUpdate.AddSnapshot.class);
    assertThat(table.ops().current().refs()).doesNotContainKey(SnapshotRef.MAIN_BRANCH);
    assertSnapshotReadable(table.ops().current(), table.ops().current().snapshots().get(0));
  }

  @Test
  void retryPersistsOnlySuccessfulAttemptKeys() {
    TestTables.TestTable table = createEncryptedTable("retry");
    ((TestTables.TestTableOperations) table.ops()).failCommits(2);

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    TableMetadata committed = table.ops().current();
    Snapshot snapshot = table.currentSnapshot();
    EncryptedKey manifestListKey = findKey(committed, snapshot.keyId());
    assertThat(manifestListKey).as("manifest list key").isNotNull();
    assertThat(keyIds(committed))
        .containsExactlyInAnyOrder(snapshot.keyId(), manifestListKey.encryptedById());
    assertSnapshotReadable(committed, snapshot);
  }

  @Test
  void restRoundTripPreservesKeySnapshotAndRefOrder() {
    TestTables.TestTable table = createEncryptedTable("rest-round-trip");

    table.newFastAppend().appendFile(TestBase.FILE_A).commit();

    UpdateTableRequest request = new UpdateTableRequest(List.of(), committedChanges);
    UpdateTableRequest parsed =
        UpdateTableRequestParser.fromJson(UpdateTableRequestParser.toJson(request));
    assertThat(parsed.updates())
        .extracting(Object::getClass)
        .containsExactly(
            MetadataUpdate.AddEncryptionKey.class,
            MetadataUpdate.AddEncryptionKey.class,
            MetadataUpdate.AddSnapshot.class,
            MetadataUpdate.SetSnapshotRef.class);

    MetadataUpdate.AddEncryptionKey keyEncryptionKey =
        (MetadataUpdate.AddEncryptionKey) parsed.updates().get(0);
    MetadataUpdate.AddEncryptionKey manifestListKey =
        (MetadataUpdate.AddEncryptionKey) parsed.updates().get(1);
    MetadataUpdate.AddSnapshot addSnapshot = (MetadataUpdate.AddSnapshot) parsed.updates().get(2);
    MetadataUpdate.SetSnapshotRef setRef = (MetadataUpdate.SetSnapshotRef) parsed.updates().get(3);
    assertThat(manifestListKey.key().encryptedById()).isEqualTo(keyEncryptionKey.key().keyId());
    assertThat(manifestListKey.key().keyId()).isEqualTo(addSnapshot.snapshot().keyId());
    assertThat(setRef.name()).isEqualTo(SnapshotRef.MAIN_BRANCH);
    assertThat(setRef.snapshotId()).isEqualTo(addSnapshot.snapshot().snapshotId());
  }

  private TestTables.TestTable createEncryptedTable(String name) {
    EncryptionManager initialEncryption = EncryptionTestHelpers.createEncryptionManager();
    File dir = temp.resolve(name).toFile();
    FileIO plainFileIO = new TestTables.LocalFileIO();
    TestTables.TestTableOperations ops =
        new TestTables.TestTableOperations(
            name, dir, EncryptingFileIO.combine(plainFileIO, initialEncryption)) {
          private EncryptionManager currentEncryption = initialEncryption;
          private FileIO currentFileIO = EncryptingFileIO.combine(plainFileIO, currentEncryption);

          @Override
          public EncryptionManager encryption() {
            return currentEncryption;
          }

          @Override
          public FileIO io() {
            return currentFileIO;
          }

          @Override
          public void commit(TableMetadata base, TableMetadata metadata) {
            TestManifestListKeyPersistence.this.committedChanges = metadata.changes();
            super.commit(base, metadata);
            this.currentEncryption = encryptionManager(current());
            this.currentFileIO = EncryptingFileIO.combine(plainFileIO, currentEncryption);
          }
        };

    return TestTables.create(
        dir, name, TestBase.SCHEMA, TestBase.SPEC, SortOrder.unsorted(), 3, ops);
  }

  private static void assertSnapshotReadable(TableMetadata metadata, Snapshot snapshot) {
    EncryptedKey manifestListKey = findKey(metadata, snapshot.keyId());
    assertThat(manifestListKey).isNotNull();
    assertThat(findKey(metadata, manifestListKey.encryptedById())).isNotNull();

    FileIO io = EncryptingFileIO.combine(new TestTables.LocalFileIO(), encryptionManager(metadata));
    assertThat(snapshot.allManifests(io)).isNotEmpty();
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
