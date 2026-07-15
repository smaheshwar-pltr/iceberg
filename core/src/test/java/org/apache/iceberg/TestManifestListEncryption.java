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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.avro.InvalidAvroMagicException;
import org.apache.iceberg.encryption.EncryptedKey;
import org.apache.iceberg.encryption.EncryptingFileIO;
import org.apache.iceberg.encryption.EncryptionManager;
import org.apache.iceberg.encryption.EncryptionTestHelpers;
import org.apache.iceberg.encryption.StandardEncryptionManager;
import org.apache.iceberg.encryption.UnitestKMS;
import org.apache.iceberg.exceptions.RuntimeIOException;
import org.apache.iceberg.inmemory.InMemoryFileIO;
import org.apache.iceberg.io.FileIO;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.apache.iceberg.types.Conversions;
import org.apache.iceberg.types.Types;
import org.junit.jupiter.api.Test;

public class TestManifestListEncryption {
  private static final String PATH = "s3://bucket/table/m1.avro";
  private static final long LENGTH = 1024L;
  private static final int SPEC_ID = 1;
  private static final long SEQ_NUM = 34L;
  private static final long MIN_SEQ_NUM = 10L;
  private static final long SNAPSHOT_ID = 987134631982734L;
  private static final int ADDED_FILES = 2;
  private static final long ADDED_ROWS = 5292L;
  private static final int EXISTING_FILES = 343;
  private static final long EXISTING_ROWS = 857273L;
  private static final int DELETED_FILES = 1;
  private static final long DELETED_ROWS = 22910L;
  private static final long FIRST_ROW_ID = 100L;
  private static final long SNAPSHOT_FIRST_ROW_ID = 130L;

  private static final ByteBuffer FIRST_SUMMARY_LOWER_BOUND =
      Conversions.toByteBuffer(Types.IntegerType.get(), 10);
  private static final ByteBuffer FIRST_SUMMARY_UPPER_BOUND =
      Conversions.toByteBuffer(Types.IntegerType.get(), 100);
  private static final ByteBuffer SECOND_SUMMARY_LOWER_BOUND =
      Conversions.toByteBuffer(Types.IntegerType.get(), 20);
  private static final ByteBuffer SECOND_SUMMARY_UPPER_BOUND =
      Conversions.toByteBuffer(Types.IntegerType.get(), 200);

  private static final List<ManifestFile.PartitionFieldSummary> PARTITION_SUMMARIES =
      Lists.newArrayList(
          new GenericPartitionFieldSummary(
              false, FIRST_SUMMARY_LOWER_BOUND, FIRST_SUMMARY_UPPER_BOUND),
          new GenericPartitionFieldSummary(
              true, false, SECOND_SUMMARY_LOWER_BOUND, SECOND_SUMMARY_UPPER_BOUND));
  private static final ByteBuffer MANIFEST_KEY_METADATA = ByteBuffer.allocate(100);

  private static final ManifestFile TEST_MANIFEST =
      new GenericManifestFile(
          PATH,
          LENGTH,
          SPEC_ID,
          ManifestContent.DATA,
          SEQ_NUM,
          MIN_SEQ_NUM,
          SNAPSHOT_ID,
          PARTITION_SUMMARIES,
          MANIFEST_KEY_METADATA,
          ADDED_FILES,
          ADDED_ROWS,
          EXISTING_FILES,
          EXISTING_ROWS,
          DELETED_FILES,
          DELETED_ROWS,
          FIRST_ROW_ID);

  @Test
  public void testEncryption() throws IOException {
    // Keys accumulate here as they are minted, mirroring how they are persisted into table
    // metadata. The manager reading a manifest list is always rebuilt from this set.
    List<EncryptedKey> metadataKeys = Lists.newArrayList();

    ManifestFile manifest = writeAndReadEncryptedManifestList(metadataKeys, 0);

    assertThat(manifest.path()).isEqualTo(PATH);
    assertThat(manifest.length()).isEqualTo(LENGTH);
    assertThat(manifest.partitionSpecId()).isEqualTo(SPEC_ID);
    assertThat(manifest.content()).isEqualTo(ManifestContent.DATA);
    assertThat(manifest.sequenceNumber()).isEqualTo(SEQ_NUM);
    assertThat(manifest.minSequenceNumber()).isEqualTo(MIN_SEQ_NUM);
    assertThat((long) manifest.snapshotId()).isEqualTo(SNAPSHOT_ID);
    assertThat((int) manifest.addedFilesCount()).isEqualTo(ADDED_FILES);
    assertThat((long) manifest.addedRowsCount()).isEqualTo(ADDED_ROWS);
    assertThat((int) manifest.existingFilesCount()).isEqualTo(EXISTING_FILES);
    assertThat((long) manifest.existingRowsCount()).isEqualTo(EXISTING_ROWS);
    assertThat((int) manifest.deletedFilesCount()).isEqualTo(DELETED_FILES);
    assertThat((long) manifest.deletedRowsCount()).isEqualTo(DELETED_ROWS);
    assertThat(manifest.content()).isEqualTo(ManifestContent.DATA);
  }

  @Test
  public void testKeyWrappingAndRotation() throws IOException {
    // The manager uses UnitestKMS.MASTER_KEY_NAME1 as the table master key.
    String tableMasterKeyID = UnitestKMS.MASTER_KEY_NAME1;

    // Keys accumulate here as they are minted, mirroring how SnapshotProducer persists each
    // snapshot's manifest-list key (and any newly minted KEK) into table metadata.
    List<EncryptedKey> metadataKeys = Lists.newArrayList();

    // Initial write/read
    writeAndReadEncryptedManifestList(metadataKeys, 0);
    // Two keys: manifest list key (metadata), and its key encryption key
    assertThat(metadataKeys).hasSize(2);
    String initialKekID = onlyKekId(metadataKeys, tableMasterKeyID);

    for (EncryptedKey key : metadataKeys) {
      if (!key.encryptedById().equals(tableMasterKeyID)) { // manifest list key metadata
        assertThat(key.encryptedById()).isEqualTo(initialKekID);
      }
    }

    assertThat(kekCount(metadataKeys, tableMasterKeyID)).isEqualTo(1);
    assertThat(mlkCount(metadataKeys, tableMasterKeyID)).isEqualTo(1);

    // Write/read after 30 days: below rotation time, key encryption key must be reused
    writeAndReadEncryptedManifestList(metadataKeys, TimeUnit.DAYS.toMillis(30));
    // Three keys: two manifest list keys (metadata), and their (still single) key encryption key
    assertThat(metadataKeys).hasSize(3);
    Set<String> intermediateKeyIds =
        metadataKeys.stream().map(EncryptedKey::keyId).collect(Collectors.toSet());
    assertThat(onlyKekId(metadataKeys, tableMasterKeyID)).isEqualTo(initialKekID);

    for (EncryptedKey key : metadataKeys) {
      if (!key.encryptedById().equals(tableMasterKeyID)) { // manifest list key metadata
        assertThat(key.encryptedById()).isEqualTo(initialKekID);
      }
    }

    assertThat(kekCount(metadataKeys, tableMasterKeyID)).isEqualTo(1);
    assertThat(mlkCount(metadataKeys, tableMasterKeyID)).isEqualTo(2);

    // Write/read after 800 days: above rotation time, a new key encryption key must be minted
    writeAndReadEncryptedManifestList(metadataKeys, TimeUnit.DAYS.toMillis(800));
    // Five keys: three manifest list keys (metadata), and two key encryption keys (old and new)
    assertThat(metadataKeys).hasSize(5);
    assertThat(kekCount(metadataKeys, tableMasterKeyID)).isEqualTo(2);
    assertThat(mlkCount(metadataKeys, tableMasterKeyID)).isEqualTo(3);

    String newKekID = null;
    int newKekCount = 0;
    int newMlkCount = 0;
    for (EncryptedKey key : metadataKeys) {
      if (intermediateKeyIds.contains(key.keyId())) {
        continue; // pre-existing key
      }

      if (key.encryptedById().equals(tableMasterKeyID)) { // new key encryption key
        newKekCount++;
        newKekID = key.keyId();
      }
    }

    // The rotated KEK differs from the original one
    assertThat(newKekID).isNotNull().isNotEqualTo(initialKekID);
    for (EncryptedKey key : metadataKeys) {
      if (intermediateKeyIds.contains(key.keyId())
          || key.encryptedById().equals(tableMasterKeyID)) {
        continue;
      }

      newMlkCount++;
      assertThat(key.encryptedById()).isEqualTo(newKekID); // new MLK wrapped by the new KEK
    }

    assertThat(newKekCount).isEqualTo(1);
    assertThat(newMlkCount).isEqualTo(1);
  }

  private static String onlyKekId(List<EncryptedKey> keys, String tableMasterKeyID) {
    return keys.stream()
        .filter(key -> key.encryptedById().equals(tableMasterKeyID))
        .map(EncryptedKey::keyId)
        .reduce(
            (a, b) -> {
              throw new IllegalStateException("Expected exactly one key encryption key");
            })
        .orElseThrow(() -> new IllegalStateException("Expected a key encryption key"));
  }

  private static long kekCount(List<EncryptedKey> keys, String tableMasterKeyID) {
    return keys.stream().filter(key -> key.encryptedById().equals(tableMasterKeyID)).count();
  }

  private static long mlkCount(List<EncryptedKey> keys, String tableMasterKeyID) {
    return keys.stream().filter(key -> !key.encryptedById().equals(tableMasterKeyID)).count();
  }

  /**
   * Writes an encrypted manifest list, then reads it back, mirroring the production key lifecycle.
   *
   * <p>The writing manager is built from {@code metadataKeys} (the keys currently "in metadata").
   * Minting returns the new manifest-list key and any newly minted key encryption key without
   * storing them; the test appends them to {@code metadataKeys}, simulating {@code
   * SnapshotProducer} persisting them. The manifest list is then read back through a fresh manager
   * built from the updated key set, mirroring a reader that loads keys from refreshed metadata.
   *
   * @param metadataKeys accumulated keys; mutated to add the keys minted by this write
   * @param timeShiftMillis clock shift applied to the writing manager, to exercise KEK rotation
   */
  private ManifestFile writeAndReadEncryptedManifestList(
      List<EncryptedKey> metadataKeys, long timeShiftMillis) throws IOException {
    FileIO io = new InMemoryFileIO();
    OutputFile outputFile = io.newOutputFile("memory:" + UUID.randomUUID());

    EncryptionManager writeManager =
        EncryptionTestHelpers.createEncryptionManager(Lists.newArrayList(metadataKeys));
    if (timeShiftMillis != 0) {
      EncryptionTestHelpers.shiftEncryptionManagerTime(writeManager, timeShiftMillis);
    }

    ManifestListWriter writer =
        ManifestLists.write(
            3,
            outputFile,
            writeManager,
            SNAPSHOT_ID,
            SNAPSHOT_ID - 1,
            SEQ_NUM,
            SNAPSHOT_FIRST_ROW_ID);
    writer.add(TEST_MANIFEST);
    writer.close();
    ManifestListFile manifestListFile = writer.toManifestListFile();

    // Persist the minted keys, exactly as SnapshotProducer.addEncryptionKeys would.
    StandardEncryptionManager.MintedKeys minted = writer.manifestListKeys();
    metadataKeys.add(minted.manifestListKey());
    if (minted.newKeyEncryptionKey() != null) {
      metadataKeys.add(minted.newKeyEncryptionKey());
    }

    // First try to read without decryption
    assertThatThrownBy(() -> ManifestLists.read(outputFile.toInputFile()))
        .isInstanceOf(RuntimeIOException.class)
        .hasMessageContaining("Failed to open file")
        .hasCauseInstanceOf(InvalidAvroMagicException.class);

    // A reader loads keys from (refreshed) metadata: build a fresh manager from the accumulated
    // set.
    EncryptionManager readManager =
        EncryptionTestHelpers.createEncryptionManager(Lists.newArrayList(metadataKeys));
    EncryptingFileIO readIO = EncryptingFileIO.combine(io, readManager);
    List<ManifestFile> manifests = ManifestLists.read(readIO.newInputFile(manifestListFile));
    assertThat(manifests.size()).isEqualTo(1);

    return manifests.get(0);
  }
}
