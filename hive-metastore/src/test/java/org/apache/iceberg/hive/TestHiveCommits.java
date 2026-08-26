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
package org.apache.iceberg.hive;

import static org.apache.iceberg.TableProperties.HIVE_LOCK_ENABLED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyBoolean;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import java.io.File;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.hadoop.hive.metastore.api.InvalidObjectException;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.CatalogUtil;
import org.apache.iceberg.DataFile;
import org.apache.iceberg.DataFiles;
import org.apache.iceberg.HasTableOperations;
import org.apache.iceberg.PartitionSpec;
import org.apache.iceberg.Snapshot;
import org.apache.iceberg.Table;
import org.apache.iceberg.TableMetadata;
import org.apache.iceberg.TableMetadataParser;
import org.apache.iceberg.TableProperties;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.encryption.EncryptingFileIO;
import org.apache.iceberg.encryption.EncryptionManager;
import org.apache.iceberg.encryption.EncryptionUtil;
import org.apache.iceberg.encryption.PlaintextEncryptionManager;
import org.apache.iceberg.encryption.UnitestKMS;
import org.apache.iceberg.exceptions.AlreadyExistsException;
import org.apache.iceberg.exceptions.CommitFailedException;
import org.apache.iceberg.exceptions.CommitStateUnknownException;
import org.apache.iceberg.exceptions.ValidationException;
import org.apache.iceberg.io.FileIO;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableMap;
import org.apache.iceberg.types.Types;
import org.apache.thrift.TException;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.platform.commons.support.ReflectionSupport;

public class TestHiveCommits extends HiveTableTestBase {
  private static final int INTERLEAVING_TIMEOUT_SECONDS = 30;

  @Test
  void plaintextRefreshIgnoresMetadataHashProperty() {
    Table retained = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations retainedOps =
        (HiveTableOperations) ((HasTableOperations) retained).operations();

    catalog
        .loadTable(TABLE_IDENTIFIER)
        .updateProperties()
        .set(HiveTableOperations.METADATA_HASH_PROP, "not-a-metadata-hash")
        .commit();

    retained.refresh();
    assertThat(retainedOps.current().properties())
        .containsEntry(HiveTableOperations.METADATA_HASH_PROP, "not-a-metadata-hash");
    assertThat(retained.encryption()).isSameAs(PlaintextEncryptionManager.instance());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        HiveTableOperations.METADATA_HASH_PROP,
        TableProperties.ENCRYPTION_TABLE_KEY,
        TableProperties.ENCRYPTION_DEK_LENGTH
      })
  void failedIntegrityRefreshRetainsAcceptedState(String hmsProperty) throws Exception {
    TableIdentifier identifier = TableIdentifier.of(DB_NAME, "encrypted_refresh");
    HiveCatalog encryptionCatalog =
        (HiveCatalog)
            CatalogUtil.loadCatalog(
                HiveCatalog.class.getName(),
                CatalogUtil.ICEBERG_CATALOG_TYPE_HIVE,
                ImmutableMap.of(CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getName()),
                HIVE_METASTORE_EXTENSION.hiveConf());

    try {
      Table retained =
          encryptionCatalog
              .buildTable(identifier, SCHEMA)
              .withPartitionSpec(PartitionSpec.unpartitioned())
              .withProperty(TableProperties.FORMAT_VERSION, "3")
              .withProperty(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1)
              .withProperty(TableProperties.ENCRYPTION_DEK_LENGTH, "24")
              .create();
      retained.refresh();
      HiveTableOperations retainedOps =
          (HiveTableOperations) ((HasTableOperations) retained).operations();
      String acceptedLocation = retainedOps.currentMetadataLocation();
      String acceptedHash =
          HIVE_METASTORE_EXTENSION
              .metastoreClient()
              .getTable(DB_NAME, identifier.name())
              .getParameters()
              .get(HiveTableOperations.METADATA_HASH_PROP);

      encryptionCatalog
          .loadTable(identifier)
          .updateSchema()
          .addColumn("data", Types.StringType.get())
          .commit();

      org.apache.hadoop.hive.metastore.api.Table hmsTable =
          HIVE_METASTORE_EXTENSION.metastoreClient().getTable(DB_NAME, identifier.name());
      String candidateLocation =
          hmsTable.getParameters().get(HiveTableOperations.METADATA_LOCATION_PROP);
      String candidateHash = hmsTable.getParameters().get(HiveTableOperations.METADATA_HASH_PROP);
      assertThat(candidateLocation).isNotEqualTo(acceptedLocation);
      assertThat(candidateHash).isNotEqualTo(acceptedHash);
      String acceptedHmsValue = hmsTable.getParameters().get(hmsProperty);
      String rejectedHmsValue =
          ImmutableMap.of(
                  HiveTableOperations.METADATA_HASH_PROP,
                  acceptedHash,
                  TableProperties.ENCRYPTION_TABLE_KEY,
                  UnitestKMS.MASTER_KEY_NAME2,
                  TableProperties.ENCRYPTION_DEK_LENGTH,
                  "32")
              .get(hmsProperty);
      assertThat(rejectedHmsValue).isNotEqualTo(acceptedHmsValue);
      hmsTable.getParameters().put(hmsProperty, rejectedHmsValue);
      HIVE_METASTORE_EXTENSION.metastoreClient().alter_table(DB_NAME, identifier.name(), hmsTable);

      try {
        assertThatThrownBy(retainedOps::refresh)
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("differs");
        assertThat(retainedOps.currentMetadataLocation()).isEqualTo(acceptedLocation);
        assertThat(retainedOps.current().schema().findField("data")).isNull();
      } finally {
        hmsTable = HIVE_METASTORE_EXTENSION.metastoreClient().getTable(DB_NAME, identifier.name());
        hmsTable.getParameters().put(hmsProperty, acceptedHmsValue);
        HIVE_METASTORE_EXTENSION
            .metastoreClient()
            .alter_table(DB_NAME, identifier.name(), hmsTable);
      }

      retainedOps.refresh();
      assertThat(retainedOps.currentMetadataLocation()).isEqualTo(candidateLocation);
      assertThat(retainedOps.current().schema().findField("data")).isNotNull();
    } finally {
      try {
        encryptionCatalog.dropTable(identifier, true);
      } finally {
        encryptionCatalog.close();
      }
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"invalid", "17"})
  void invalidDekCommitIsRejected(String invalidDekLength) throws Exception {
    TableIdentifier identifier = TableIdentifier.of(DB_NAME, "invalid_dek_commit");
    HiveCatalog encryptionCatalog =
        (HiveCatalog)
            CatalogUtil.loadCatalog(
                HiveCatalog.class.getName(),
                CatalogUtil.ICEBERG_CATALOG_TYPE_HIVE,
                ImmutableMap.of(CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getName()),
                HIVE_METASTORE_EXTENSION.hiveConf());

    try {
      Table retained =
          encryptionCatalog
              .buildTable(identifier, SCHEMA)
              .withPartitionSpec(PartitionSpec.unpartitioned())
              .withProperty(TableProperties.FORMAT_VERSION, "3")
              .withProperty(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1)
              .withProperty(TableProperties.ENCRYPTION_DEK_LENGTH, "24")
              .create();
      retained.refresh();
      HiveTableOperations retainedOps =
          (HiveTableOperations) ((HasTableOperations) retained).operations();
      String acceptedLocation = retainedOps.currentMetadataLocation();

      assertThatThrownBy(
              () ->
                  encryptionCatalog
                      .loadTable(identifier)
                      .updateProperties()
                      .set(TableProperties.ENCRYPTION_DEK_LENGTH, invalidDekLength)
                      .commit())
          .isInstanceOf(ValidationException.class)
          .hasMessage("Invalid data key length: %s (must be 16, 24, or 32)", invalidDekLength);

      retained.refresh();
      assertThat(retainedOps.currentMetadataLocation()).isEqualTo(acceptedLocation);
      assertThat(retainedOps.current().properties())
          .containsEntry(TableProperties.ENCRYPTION_DEK_LENGTH, "24");
      org.apache.hadoop.hive.metastore.api.Table hmsTable =
          HIVE_METASTORE_EXTENSION.metastoreClient().getTable(DB_NAME, identifier.name());
      assertThat(hmsTable.getParameters())
          .containsEntry(HiveTableOperations.METADATA_LOCATION_PROP, acceptedLocation)
          .containsEntry(TableProperties.ENCRYPTION_DEK_LENGTH, "24");
    } finally {
      try {
        encryptionCatalog.dropTable(identifier, true);
      } finally {
        encryptionCatalog.close();
      }
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"invalid", "17"})
  void invalidDekRefreshRetainsAcceptedState(String invalidDekLength) throws Exception {
    TableIdentifier identifier = TableIdentifier.of(DB_NAME, "invalid_dek_refresh");
    HiveCatalog encryptionCatalog =
        (HiveCatalog)
            CatalogUtil.loadCatalog(
                HiveCatalog.class.getName(),
                CatalogUtil.ICEBERG_CATALOG_TYPE_HIVE,
                ImmutableMap.of(CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getName()),
                HIVE_METASTORE_EXTENSION.hiveConf());

    try {
      Table retained =
          encryptionCatalog
              .buildTable(identifier, SCHEMA)
              .withPartitionSpec(PartitionSpec.unpartitioned())
              .withProperty(TableProperties.FORMAT_VERSION, "3")
              .withProperty(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1)
              .withProperty(TableProperties.ENCRYPTION_DEK_LENGTH, "24")
              .create();
      retained.refresh();
      HiveTableOperations retainedOps =
          (HiveTableOperations) ((HasTableOperations) retained).operations();
      TableMetadata acceptedMetadata = retainedOps.current();
      String acceptedLocation = retainedOps.currentMetadataLocation();
      EncryptionManager acceptedManager = retainedOps.encryption();
      FileIO acceptedFileIO = retainedOps.io();
      org.apache.hadoop.hive.metastore.api.Table hmsTable =
          HIVE_METASTORE_EXTENSION.metastoreClient().getTable(DB_NAME, identifier.name());
      String acceptedHash = hmsTable.getParameters().get(HiveTableOperations.METADATA_HASH_PROP);

      TableMetadata candidateMetadata =
          TableMetadata.buildFrom(acceptedMetadata)
              .setProperties(
                  ImmutableMap.of(TableProperties.ENCRYPTION_DEK_LENGTH, invalidDekLength))
              .build();
      String candidateLocation =
          retainedOps.metadataFileLocation("injected-" + invalidDekLength + ".metadata.json");
      TableMetadataParser.overwrite(
          candidateMetadata, acceptedFileIO.newOutputFile(candidateLocation));
      hmsTable.getParameters().put(HiveTableOperations.METADATA_LOCATION_PROP, candidateLocation);
      hmsTable.getParameters().put(TableProperties.ENCRYPTION_DEK_LENGTH, invalidDekLength);
      HMSTablePropertyHelper.setMetadataHash(candidateMetadata, hmsTable.getParameters());
      HIVE_METASTORE_EXTENSION.metastoreClient().alter_table(DB_NAME, identifier.name(), hmsTable);

      try {
        assertThatThrownBy(retainedOps::refresh)
            .isInstanceOf(ValidationException.class)
            .hasMessage("Invalid data key length: %s (must be 16, 24, or 32)", invalidDekLength);
        assertThat(retainedOps.currentMetadataLocation()).isEqualTo(acceptedLocation);
        assertThat(retainedOps.current()).isSameAs(acceptedMetadata);
        assertThat(retainedOps.current().properties())
            .containsEntry(TableProperties.ENCRYPTION_DEK_LENGTH, "24");
        assertThat(retainedOps.encryption()).isSameAs(acceptedManager);
        assertThat(retainedOps.io()).isSameAs(acceptedFileIO);
      } finally {
        hmsTable = HIVE_METASTORE_EXTENSION.metastoreClient().getTable(DB_NAME, identifier.name());
        hmsTable.getParameters().put(HiveTableOperations.METADATA_LOCATION_PROP, acceptedLocation);
        hmsTable.getParameters().put(HiveTableOperations.METADATA_HASH_PROP, acceptedHash);
        hmsTable.getParameters().put(TableProperties.ENCRYPTION_DEK_LENGTH, "24");
        HIVE_METASTORE_EXTENSION
            .metastoreClient()
            .alter_table(DB_NAME, identifier.name(), hmsTable);
        acceptedFileIO.deleteFile(candidateLocation);
      }
    } finally {
      try {
        encryptionCatalog.dropTable(identifier, true);
      } finally {
        encryptionCatalog.close();
      }
    }
  }

  @Test
  void refreshPublishesMetadataWithEncryptionState() throws Exception {
    TableIdentifier identifier = TableIdentifier.of(DB_NAME, "refresh_file_io");
    HiveCatalog encryptionCatalog =
        (HiveCatalog)
            CatalogUtil.loadCatalog(
                HiveCatalog.class.getName(),
                CatalogUtil.ICEBERG_CATALOG_TYPE_HIVE,
                ImmutableMap.of(CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getName()),
                HIVE_METASTORE_EXTENSION.hiveConf());

    try {
      Table retained =
          encryptionCatalog
              .buildTable(identifier, SCHEMA)
              .withPartitionSpec(PartitionSpec.unpartitioned())
              .withProperty(TableProperties.FORMAT_VERSION, "3")
              .withProperty(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1)
              .create();
      retained.refresh();
      HiveTableOperations retainedOps =
          (HiveTableOperations) ((HasTableOperations) retained).operations();
      EncryptionManager priorManager = retainedOps.encryption();

      Table concurrent = encryptionCatalog.loadTable(identifier);
      DataFile file =
          DataFiles.builder(concurrent.spec())
              .withPath(concurrent.location() + "/data.parquet")
              .withRecordCount(1)
              .withFileSizeInBytes(1)
              .build();
      concurrent.newFastAppend().appendFile(file).commit();
      Snapshot concurrentSnapshot = concurrent.currentSnapshot();
      assertThat(concurrentSnapshot.keyId()).isNotNull();
      assertThat(EncryptionUtil.encryptionKeys(priorManager))
          .doesNotContainKey(concurrentSnapshot.keyId());

      HiveTableOperations spyOps = spy(retainedOps);
      CountDownLatch managerSelected = new CountDownLatch(1);
      CountDownLatch publishFileIO = new CountDownLatch(1);
      CountDownLatch firstCurrentReturned = new CountDownLatch(1);
      CountDownLatch refreshFinished = new CountDownLatch(1);
      AtomicBoolean blockNextEncryption = new AtomicBoolean(true);
      AtomicReference<EncryptionManager> selectedManager = new AtomicReference<>();
      doAnswer(
              invocation -> {
                EncryptionManager manager = (EncryptionManager) invocation.callRealMethod();
                if (blockNextEncryption.compareAndSet(true, false)) {
                  selectedManager.set(manager);
                  managerSelected.countDown();
                  if (!publishFileIO.await(INTERLEAVING_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new AssertionError("Timed out waiting to publish FileIO");
                  }
                }

                return manager;
              })
          .when(spyOps)
          .encryption();

      AtomicReference<FileIO> overlappingFileIO = new AtomicReference<>();
      AtomicReference<Snapshot> observedSnapshot = new AtomicReference<>();
      AtomicReference<Throwable> asyncFailure = new AtomicReference<>();
      Thread ioThread =
          new Thread(
              () -> {
                try {
                  overlappingFileIO.set(spyOps.io());
                } catch (Throwable t) {
                  asyncFailure.compareAndSet(null, t);
                }
              },
              "hive-encryption-io");
      Thread refreshThread =
          new Thread(
              () -> {
                try {
                  spyOps.refresh();
                } catch (Throwable t) {
                  asyncFailure.compareAndSet(null, t);
                } finally {
                  refreshFinished.countDown();
                }
              },
              "hive-encryption-refresh");
      Thread currentThread =
          new Thread(
              () -> {
                try {
                  spyOps.current();
                  firstCurrentReturned.countDown();
                  if (!refreshFinished.await(INTERLEAVING_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new AssertionError("Timed out waiting for refresh");
                  }

                  observedSnapshot.set(spyOps.current().currentSnapshot());
                } catch (Throwable t) {
                  firstCurrentReturned.countDown();
                  asyncFailure.compareAndSet(null, t);
                }
              },
              "hive-encryption-current");

      try {
        ioThread.start();
        assertThat(managerSelected.await(INTERLEAVING_TIMEOUT_SECONDS, TimeUnit.SECONDS))
            .as("FileIO selected its encryption manager")
            .isTrue();
        assertThat(selectedManager).hasValue(priorManager);

        refreshThread.start();
        awaitBlocked(refreshThread);

        currentThread.start();
        awaitBlockedBeforeReturn(currentThread, firstCurrentReturned);
      } finally {
        publishFileIO.countDown();
        ioThread.join(TimeUnit.SECONDS.toMillis(INTERLEAVING_TIMEOUT_SECONDS));
        refreshThread.join(TimeUnit.SECONDS.toMillis(INTERLEAVING_TIMEOUT_SECONDS));
        currentThread.join(TimeUnit.SECONDS.toMillis(INTERLEAVING_TIMEOUT_SECONDS));
      }

      assertThat(ioThread.isAlive()).as("FileIO thread completed").isFalse();
      assertThat(refreshThread.isAlive()).as("refresh thread completed").isFalse();
      assertThat(currentThread.isAlive()).as("current thread completed").isFalse();
      assertThat(asyncFailure.get()).isNull();

      assertThat(overlappingFileIO.get()).isInstanceOf(EncryptingFileIO.class);
      assertThat(((EncryptingFileIO) overlappingFileIO.get()).encryptionManager())
          .isSameAs(priorManager);

      FileIO refreshedFileIO = spyOps.io();
      EncryptionManager refreshedManager = spyOps.encryption();
      assertThat(refreshedFileIO).isInstanceOf(EncryptingFileIO.class);
      assertThat(((EncryptingFileIO) refreshedFileIO).encryptionManager())
          .isSameAs(refreshedManager)
          .isNotSameAs(priorManager);
      assertThat(EncryptionUtil.encryptionKeys(refreshedManager))
          .containsKey(concurrentSnapshot.keyId());
      Snapshot refreshedSnapshot = observedSnapshot.get();
      assertThat(refreshedSnapshot.snapshotId()).isEqualTo(concurrentSnapshot.snapshotId());
      assertThat(refreshedSnapshot.allManifests(refreshedFileIO)).hasSize(1);
    } finally {
      try {
        encryptionCatalog.dropTable(identifier, true);
      } finally {
        encryptionCatalog.close();
      }
    }
  }

  @Test
  public void testSuppressUnlockExceptions() {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    AtomicReference<HiveLock> lockRef = new AtomicReference<>();

    when(spyOps.lockObject(metadataV2))
        .thenAnswer(
            i -> {
              HiveLock lock = (HiveLock) i.callRealMethod();
              lockRef.set(lock);
              return lock;
            });

    try {
      spyOps.commit(metadataV2, metadataV1);
      HiveLock spyLock = spy(lockRef.get());
      doThrow(new RuntimeException()).when(spyLock).unlock();
    } finally {
      lockRef.get().unlock();
    }

    ops.refresh();

    // the commit must succeed
    assertThat(ops.current().schema().columns()).hasSize(1);
  }

  /**
   * Pretends we throw an error while persisting, and not found with check state, commit state
   * should be treated as unknown, because in reality the persisting may still succeed, just not yet
   * by the time of checking.
   */
  @Test
  public void testThriftExceptionUnknownStateIfNotInHistoryFailureOnCommit()
      throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    failCommitAndThrowException(spyOps);

    assertThatThrownBy(() -> spyOps.commit(metadataV2, metadataV1))
        .isInstanceOf(CommitStateUnknownException.class)
        .hasMessageStartingWith("Datacenter on fire");

    ops.refresh();
    assertThat(ops.current()).as("Current metadata should not have changed").isEqualTo(metadataV2);
    assertThat(metadataFileExists(metadataV2)).as("Current metadata should still exist").isTrue();
    assertThat(metadataFileCount(ops.current()))
        .as(
            "New metadata files should still exist, new location not in history but"
                + " the commit may still succeed")
        .isEqualTo(3);
  }

  /** Pretends we throw an error while persisting that actually does commit serverside */
  @Test
  public void testThriftExceptionSuccessOnCommit() throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    // Simulate a communication error after a successful commit
    commitAndThrowException(ops, spyOps);

    // Shouldn't throw because the commit actually succeeds even though persistTable throws an
    // exception
    spyOps.commit(metadataV2, metadataV1);

    ops.refresh();
    assertThat(ops.current()).as("Current metadata should have changed").isNotEqualTo(metadataV2);
    assertThat(metadataFileExists(ops.current()))
        .as("Current metadata file should still exist")
        .isTrue();
    assertThat(metadataFileCount(ops.current()))
        .as("Commit should have been successful and new metadata file should be made")
        .isEqualTo(3);
  }

  /**
   * Pretends we throw an exception while persisting and don't know what happened, can't check to
   * find out, but in reality the commit failed
   */
  @Test
  public void testThriftExceptionUnknownFailedCommit() throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    failCommitAndThrowException(spyOps);
    breakFallbackCatalogCommitCheck(spyOps);

    assertThatThrownBy(() -> spyOps.commit(metadataV2, metadataV1))
        .isInstanceOf(CommitStateUnknownException.class)
        .hasMessageStartingWith("Datacenter on fire");

    ops.refresh();

    assertThat(ops.current()).as("Current metadata should not have changed").isEqualTo(metadataV2);
    assertThat(metadataFileExists(ops.current()))
        .as("Current metadata file should still exist")
        .isTrue();
    assertThat(metadataFileCount(ops.current()))
        .as("Client could not determine outcome so new metadata file should also exist")
        .isEqualTo(3);
  }

  /**
   * Pretends we throw an exception while persisting and don't know what happened, can't check to
   * find out, but in reality the commit succeeded
   */
  @Test
  public void testThriftExceptionsUnknownSuccessCommit() throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    commitAndThrowException(ops, spyOps);
    breakFallbackCatalogCommitCheck(spyOps);

    assertThatThrownBy(() -> spyOps.commit(metadataV2, metadataV1))
        .isInstanceOf(CommitStateUnknownException.class)
        .hasMessageStartingWith("Datacenter on fire");

    ops.refresh();

    assertThat(ops.current()).as("Current metadata should have changed").isNotEqualTo(metadataV2);
    assertThat(metadataFileExists(ops.current()))
        .as("Current metadata file should still exist")
        .isTrue();
  }

  /**
   * Pretends we threw an exception while persisting, the commit succeeded, the lock expired, and a
   * second committer placed a commit on top of ours before the first committer was able to check if
   * their commit succeeded or not
   *
   * <p>Timeline:
   *
   * <ul>
   *   <li>Client 1 commits which throws an exception but succeeded
   *   <li>Client 1's lock expires while waiting to do the recheck for commit success
   *   <li>Client 2 acquires a lock, commits successfully on top of client 1's commit and release
   *       lock
   *   <li>Client 1 check's to see if their commit was successful
   * </ul>
   *
   * <p>This tests to make sure a disconnected client 1 doesn't think their commit failed just
   * because it isn't the current one during the recheck phase.
   */
  @Test
  public void testThriftExceptionConcurrentCommit() throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    AtomicReference<HiveLock> lock = new AtomicReference<>();
    doAnswer(
            l -> {
              lock.set(ops.lockObject(metadataV2));
              return lock.get();
            })
        .when(spyOps)
        .lockObject(metadataV2);

    concurrentCommitAndThrowException(ops, spyOps, table, lock);

    /*
    This commit and our concurrent commit should succeed even though this commit throws an exception
    after the persist operation succeeds
     */
    spyOps.commit(metadataV2, metadataV1);

    ops.refresh();
    assertThat(ops.current()).as("Current metadata should have changed").isNotEqualTo(metadataV2);
    assertThat(metadataFileExists(ops.current()))
        .as("Current metadata file should still exist")
        .isTrue();
    assertThat(ops.current().schema().columns())
        .as("The column addition from the concurrent commit should have been successful")
        .hasSize(2);
  }

  @Test
  public void testInvalidObjectException() {
    TableIdentifier badTi = TableIdentifier.of(DB_NAME, "`tbl`");
    assertThatThrownBy(() -> catalog.createTable(badTi, SCHEMA, PartitionSpec.unpartitioned()))
        .isInstanceOf(ValidationException.class)
        .hasMessage("Invalid Hive object for %s.%s", DB_NAME, "`tbl`");
  }

  @Test
  public void testAlreadyExistsException() {
    assertThatThrownBy(
            () -> catalog.createTable(TABLE_IDENTIFIER, SCHEMA, PartitionSpec.unpartitioned()))
        .isInstanceOf(AlreadyExistsException.class)
        .hasMessage("Table already exists: %s.%s", DB_NAME, TABLE_NAME);
  }

  /** Uses NoLock and pretends we throw an error because of a concurrent commit */
  @Test
  public void testNoLockThriftExceptionConcurrentCommit() throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    // Sets NoLock
    doReturn(new NoLock()).when(spyOps).lockObject(any());

    // Simulate a concurrent table modification error
    doThrow(
            new RuntimeException(
                "MetaException(message:The table has been modified. The parameter value for key 'metadata_location' is"))
        .when(spyOps)
        .persistTable(any(), anyBoolean(), any());

    // Should throw a CommitFailedException so the commit could be retried
    assertThatThrownBy(() -> spyOps.commit(metadataV2, metadataV1))
        .isInstanceOf(CommitFailedException.class)
        .hasMessage("The table hivedb.tbl has been modified concurrently");

    ops.refresh();
    assertThat(ops.current()).as("Current metadata should not have changed").isEqualTo(metadataV2);
    assertThat(metadataFileExists(metadataV2)).as("Current metadata should still exist").isTrue();
    assertThat(metadataFileCount(ops.current()))
        .as("New metadata files should not exist")
        .isEqualTo(2);
  }

  @Test
  public void testLockExceptionUnknownSuccessCommit() throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    // Simulate a communication error after a successful commit
    doAnswer(
            i -> {
              org.apache.hadoop.hive.metastore.api.Table tbl =
                  i.getArgument(0, org.apache.hadoop.hive.metastore.api.Table.class);
              String location = i.getArgument(2, String.class);
              ops.persistTable(tbl, true, location);
              throw new LockException("Datacenter on fire");
            })
        .when(spyOps)
        .persistTable(any(), anyBoolean(), any());

    assertThatThrownBy(() -> spyOps.commit(metadataV2, metadataV1))
        .hasMessageContaining("Failed to heartbeat for hive lock while")
        .isInstanceOf(CommitStateUnknownException.class);

    ops.refresh();

    assertThat(ops.current().location())
        .as("Current metadata should have changed to metadata V1")
        .isEqualTo(metadataV1.location());
    assertThat(metadataFileExists(ops.current()))
        .as("Current metadata file should still exist")
        .isTrue();
  }

  @Test
  public void testSuccessCommitWhenCheckCommitStatusOOM() throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();

    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    TableMetadata metadataV2 = ops.current();

    assertThat(ops.current().schema().columns()).hasSize(2);

    HiveTableOperations spyOps = spy(ops);

    // Simulate a communication error after a successful commit
    doAnswer(
            i -> {
              org.apache.hadoop.hive.metastore.api.Table tbl =
                  i.getArgument(0, org.apache.hadoop.hive.metastore.api.Table.class);
              String location = i.getArgument(2, String.class);
              ops.persistTable(tbl, true, location);
              throw new UnknownError();
            })
        .when(spyOps)
        .persistTable(any(), anyBoolean(), any());
    try {
      ReflectionSupport.invokeMethod(
          ops.getClass()
              .getSuperclass()
              .getDeclaredMethod("checkCommitStatus", String.class, TableMetadata.class),
          doThrow(new OutOfMemoryError()).when(spyOps),
          anyString(),
          any());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    assertThatThrownBy(() -> spyOps.commit(metadataV2, metadataV1))
        .isInstanceOf(OutOfMemoryError.class)
        .hasMessage(null);

    ops.refresh();

    assertThat(ops.current().location())
        .as("Current metadata should have changed to metadata V1")
        .isEqualTo(metadataV1.location());
    assertThat(metadataFileExists(ops.current()))
        .as("Current metadata file should still exist")
        .isTrue();
  }

  @Test
  public void testCommitExceptionWithoutMessage() throws TException, InterruptedException {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();

    TableMetadata metadataV1 = ops.current();
    table.updateSchema().addColumn("n", Types.IntegerType.get()).commit();

    ops.refresh();

    HiveTableOperations spyOps = spy(ops);
    doThrow(new RuntimeException()).when(spyOps).persistTable(any(), anyBoolean(), any());

    assertThatThrownBy(() -> spyOps.commit(ops.current(), metadataV1))
        .isInstanceOf(CommitStateUnknownException.class)
        .hasMessageStartingWith("null\nCannot determine whether the commit was successful or not");
  }

  @Test
  public void testChangeLockWithAlterTable() throws Exception {
    Table table = catalog.loadTable(TABLE_IDENTIFIER);
    HiveTableOperations ops = (HiveTableOperations) ((HasTableOperations) table).operations();
    TableMetadata base = ops.current();
    final HiveLock initialLock = ops.lockObject(base);

    AtomicReference<HiveLock> lockRef = new AtomicReference<>();
    HiveTableOperations spyOps = spy(ops);
    doAnswer(
            i -> {
              lockRef.set(ops.lockObject(i.getArgument(0)));
              return lockRef.get();
            })
        .when(spyOps)
        .lockObject(base);

    TableMetadata newMetadata =
        TableMetadata.buildFrom(base)
            .setProperties(
                ImmutableMap.of(
                    HIVE_LOCK_ENABLED, initialLock instanceof NoLock ? "true" : "false"))
            .build();
    spyOps.commit(base, newMetadata);

    assertThat(lockRef).as("Lock not captured by the stub").doesNotHaveNullValue();
    assertThat(lockRef.get())
        .as("New lock mechanism shouldn't take effect before the commit completes")
        .hasSameClassAs(initialLock);
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  @NullSource
  public void testFirstHiveCommitWithLockSetting(Boolean lockEnabled) {
    TableIdentifier newTableIdentifier = TableIdentifier.of(DB_NAME, "lock_test_table");

    try {
      HiveTableOperations ops =
          new HiveTableOperations(
              catalog.getConf(),
              catalog.clientPool(),
              catalog.newTableOps(newTableIdentifier).io(),
              null,
              catalog.name(),
              newTableIdentifier.namespace().level(0),
              newTableIdentifier.name());

      AtomicReference<HiveLock> lockRef = new AtomicReference<>();
      HiveTableOperations spyOps = spy(ops);
      TableMetadata metadata =
          TableMetadata.newTableMetadata(
              SCHEMA,
              PartitionSpec.unpartitioned(),
              catalog.defaultWarehouseLocation(newTableIdentifier),
              lockEnabled == null
                  ? ImmutableMap.of()
                  : ImmutableMap.of(HIVE_LOCK_ENABLED, String.valueOf(lockEnabled)));
      doAnswer(
              i -> {
                lockRef.set(ops.lockObject(i.getArgument(0)));
                return lockRef.get();
              })
          .when(spyOps)
          .lockObject(eq(metadata));

      // Commit with base = null (new table creation)
      spyOps.commit(null, metadata);

      Class<? extends HiveLock> expectedLockClass =
          Boolean.FALSE.equals(lockEnabled) ? NoLock.class : MetastoreLock.class;
      assertThat(lockRef).as("Lock not captured by the stub").doesNotHaveNullValue();
      assertThat(lockRef)
          .as("Lock mechanism should use (%s)", expectedLockClass.getSimpleName())
          .hasValueMatching(lock -> lock.getClass().equals(expectedLockClass));
    } finally {
      catalog.dropTable(newTableIdentifier, true);
    }
  }

  @Test
  void failedEncryptedCreateDoesNotInstallEncryptionState() throws Exception {
    TableIdentifier tableIdent = TableIdentifier.of(DB_NAME, "failed_encrypted_create");
    UnitestKMS kms = new UnitestKMS();
    kms.initialize(ImmutableMap.of());
    HiveTableOperations ops =
        new HiveTableOperations(
            catalog.getConf(),
            catalog.clientPool(),
            catalog.newTableOps(tableIdent).io(),
            kms,
            catalog.name(),
            tableIdent.namespace().level(0),
            tableIdent.name());
    FileIO rawFileIO = ops.io();
    HiveTableOperations spyOps = spy(ops);
    TableMetadata metadata =
        TableMetadata.newTableMetadata(
            SCHEMA,
            PartitionSpec.unpartitioned(),
            catalog.defaultWarehouseLocation(tableIdent),
            ImmutableMap.of(
                TableProperties.FORMAT_VERSION,
                "3",
                TableProperties.ENCRYPTION_TABLE_KEY,
                UnitestKMS.MASTER_KEY_NAME1));
    doThrow(new InvalidObjectException("Rejected table"))
        .when(spyOps)
        .persistTable(any(), anyBoolean(), any());

    try {
      assertThatThrownBy(() -> spyOps.commit(null, metadata))
          .isInstanceOf(ValidationException.class)
          .hasMessage("Invalid Hive object for %s.%s", DB_NAME, tableIdent.name());
      assertThat(spyOps.encryption()).isSameAs(PlaintextEncryptionManager.instance());
      assertThat(spyOps.io()).isSameAs(rawFileIO);
      assertThat(catalog.tableExists(tableIdent)).isFalse();
    } finally {
      catalog.dropTable(tableIdent, true);
    }
  }

  @Test
  void encryptedCreateStatusRecoveryPreservesConcurrentSnapshotKeys() throws Exception {
    TableIdentifier tableIdent = TableIdentifier.of(DB_NAME, "encrypted_create_status_recovery");
    HiveCatalog encryptedCatalog =
        (HiveCatalog)
            CatalogUtil.loadCatalog(
                HiveCatalog.class.getName(),
                "encrypted-create-status-recovery",
                ImmutableMap.of(CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getName()),
                HIVE_METASTORE_EXTENSION.hiveConf());

    try {
      HiveTableOperations ops = (HiveTableOperations) encryptedCatalog.newTableOps(tableIdent);
      HiveTableOperations spyOps = spy(ops);
      TableMetadata metadata =
          TableMetadata.newTableMetadata(
              SCHEMA,
              PartitionSpec.unpartitioned(),
              encryptedCatalog.defaultWarehouseLocation(tableIdent),
              ImmutableMap.of(
                  TableProperties.FORMAT_VERSION,
                  "3",
                  TableProperties.ENCRYPTION_TABLE_KEY,
                  UnitestKMS.MASTER_KEY_NAME1));
      AtomicReference<HiveLock> lock = new AtomicReference<>();
      AtomicReference<Snapshot> concurrentSnapshot = new AtomicReference<>();
      doAnswer(
              ignored -> {
                lock.set(ops.lockObject(metadata));
                return lock.get();
              })
          .when(spyOps)
          .lockObject(metadata);
      doAnswer(
              invocation -> {
                boolean updateHiveTable = invocation.getArgument(1, Boolean.class);
                String metadataLocation = invocation.getArgument(2, String.class);
                ops.persistTable(invocation.getArgument(0), updateHiveTable, metadataLocation);

                lock.get().unlock();
                Table concurrentTable = encryptedCatalog.loadTable(tableIdent);
                DataFile file =
                    DataFiles.builder(concurrentTable.spec())
                        .withPath(concurrentTable.location() + "/data.parquet")
                        .withRecordCount(1)
                        .withFileSizeInBytes(1)
                        .build();
                concurrentTable.newFastAppend().appendFile(file).commit();
                concurrentTable.refresh();
                concurrentSnapshot.set(concurrentTable.currentSnapshot());
                throw new TException("Datacenter on fire");
              })
          .when(spyOps)
          .persistTable(any(), anyBoolean(), any());

      spyOps.commit(null, metadata);

      Snapshot snapshot = concurrentSnapshot.get();
      FileIO retainedFileIO = spyOps.io();
      assertThat(snapshot).isNotNull();
      assertThat(snapshot.keyId()).isNotNull();
      assertThat(retainedFileIO).isInstanceOf(EncryptingFileIO.class);
      assertThat(snapshot.allManifests(retainedFileIO)).hasSize(1);
    } finally {
      encryptedCatalog.dropTable(tableIdent, true);
      encryptedCatalog.close();
    }
  }

  private void commitAndThrowException(
      HiveTableOperations realOperations, HiveTableOperations spyOperations)
      throws TException, InterruptedException {
    // Simulate a communication error after a successful commit
    doAnswer(
            i -> {
              org.apache.hadoop.hive.metastore.api.Table tbl =
                  i.getArgument(0, org.apache.hadoop.hive.metastore.api.Table.class);
              String location = i.getArgument(2, String.class);
              realOperations.persistTable(tbl, true, location);
              throw new TException("Datacenter on fire");
            })
        .when(spyOperations)
        .persistTable(any(), anyBoolean(), any());
  }

  private void concurrentCommitAndThrowException(
      HiveTableOperations realOperations,
      HiveTableOperations spyOperations,
      Table table,
      AtomicReference<HiveLock> lock)
      throws TException, InterruptedException {
    // Simulate a communication error after a successful commit
    doAnswer(
            i -> {
              org.apache.hadoop.hive.metastore.api.Table tbl =
                  i.getArgument(0, org.apache.hadoop.hive.metastore.api.Table.class);
              String location = i.getArgument(2, String.class);
              realOperations.persistTable(tbl, true, location);
              // Simulate lock expiration or removal
              lock.get().unlock();
              table.refresh();
              table.updateSchema().addColumn("newCol", Types.IntegerType.get()).commit();
              throw new TException("Datacenter on fire");
            })
        .when(spyOperations)
        .persistTable(any(), anyBoolean(), any());
  }

  private void failCommitAndThrowException(HiveTableOperations spyOperations)
      throws TException, InterruptedException {
    doThrow(new TException("Datacenter on fire"))
        .when(spyOperations)
        .persistTable(any(), anyBoolean(), any());
  }

  private void breakFallbackCatalogCommitCheck(HiveTableOperations spyOperations) {
    when(spyOperations.refresh())
        .thenThrow(new RuntimeException("Still on fire")); // Failure on commit check
  }

  private boolean metadataFileExists(TableMetadata metadata) {
    return new File(metadata.metadataFileLocation().replace("file:", "")).exists();
  }

  private int metadataFileCount(TableMetadata metadata) {
    return new File(metadata.metadataFileLocation().replace("file:", ""))
        .getParentFile()
        .listFiles(file -> file.getName().endsWith("metadata.json"))
        .length;
  }

  private static void awaitBlocked(Thread thread) {
    Awaitility.await()
        .atMost(Duration.ofSeconds(INTERLEAVING_TIMEOUT_SECONDS))
        .until(() -> !thread.isAlive() || thread.getState() == Thread.State.BLOCKED);
    assertThat(thread.getState())
        .as("%s is blocked", thread.getName())
        .isEqualTo(Thread.State.BLOCKED);
  }

  private static void awaitBlockedBeforeReturn(Thread thread, CountDownLatch returned) {
    Awaitility.await()
        .atMost(Duration.ofSeconds(INTERLEAVING_TIMEOUT_SECONDS))
        .until(() -> returned.getCount() == 0 || thread.getState() == Thread.State.BLOCKED);
    assertThat(returned.getCount()).as("Current metadata is not published").isOne();
    assertThat(thread.getState())
        .as("%s is blocked", thread.getName())
        .isEqualTo(Thread.State.BLOCKED);
  }
}
