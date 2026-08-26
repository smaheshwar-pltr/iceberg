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
package org.apache.iceberg.spark.sql;

import static org.apache.iceberg.Files.localInput;
import static org.apache.iceberg.types.Types.NestedField.optional;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.ChecksumFileSystem;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.iceberg.AppendFiles;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.DataFile;
import org.apache.iceberg.DataFiles;
import org.apache.iceberg.FileScanTask;
import org.apache.iceberg.HasTableOperations;
import org.apache.iceberg.MetadataTableType;
import org.apache.iceberg.Parameters;
import org.apache.iceberg.Schema;
import org.apache.iceberg.Snapshot;
import org.apache.iceberg.Table;
import org.apache.iceberg.TableMetadata;
import org.apache.iceberg.TableProperties;
import org.apache.iceberg.Transaction;
import org.apache.iceberg.encryption.Ciphers;
import org.apache.iceberg.encryption.EncryptedKey;
import org.apache.iceberg.encryption.EncryptingFileIO;
import org.apache.iceberg.encryption.PlaintextEncryptionManager;
import org.apache.iceberg.encryption.UnitestKMS;
import org.apache.iceberg.exceptions.NoSuchTableException;
import org.apache.iceberg.exceptions.ValidationException;
import org.apache.iceberg.io.CloseableIterable;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.SeekableInputStream;
import org.apache.iceberg.parquet.Parquet;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableList;
import org.apache.iceberg.relocated.com.google.common.collect.Maps;
import org.apache.iceberg.relocated.com.google.common.collect.Streams;
import org.apache.iceberg.spark.CatalogTestBase;
import org.apache.iceberg.spark.Spark3Util;
import org.apache.iceberg.spark.SparkCatalogConfig;
import org.apache.iceberg.types.Types;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.spark.SparkException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.mockito.internal.util.collections.Iterables;

public class TestTableEncryption extends CatalogTestBase {
  private static final int INTERLEAVING_TIMEOUT_SECONDS = 30;

  private Path tableLocation;

  private static Map<String, String> appendCatalogEncryptionProperties(Map<String, String> props) {
    Map<String, String> newProps = Maps.newHashMap();
    newProps.putAll(props);
    newProps.put(CatalogProperties.ENCRYPTION_KMS_IMPL, CoordinatedKMS.class.getName());
    return newProps;
  }

  @Parameters(name = "catalogName = {0}, implementation = {1}, config = {2}")
  protected static Object[][] parameters() {
    return new Object[][] {
      {
        SparkCatalogConfig.HIVE.catalogName(),
        SparkCatalogConfig.HIVE.implementation(),
        appendCatalogEncryptionProperties(SparkCatalogConfig.HIVE.properties())
      }
    };
  }

  @BeforeEach
  public void createTables() throws Exception {
    CoordinatedKMS.reset();
    sql(
        "CREATE TABLE %s (id bigint, data string, float float) USING iceberg "
            + "TBLPROPERTIES ( "
            + "'encryption.key-id'='%s', 'format-version'='3')",
        tableName, UnitestKMS.MASTER_KEY_NAME1);

    this.tableLocation = new Path(Spark3Util.loadIcebergTable(spark, tableName).location());
    sql("INSERT INTO %s VALUES (1, 'a', 1.0), (2, 'b', 2.0), (3, 'c', float('NaN'))", tableName);
  }

  @AfterEach
  public void removeTables() throws IOException {
    CoordinatedKMS.reset();
    sql("DROP TABLE IF EXISTS %s", tableName);

    FileSystem fs = tableLocation.getFileSystem(hiveConf);
    Path qualifiedTableLocation = fs.makeQualified(tableLocation);
    Path metastoreRoot = fs.makeQualified(new Path(new File(dbPath("default")).getParent()));
    Path expectedTableLocation = new Path(metastoreRoot, tableIdent.name());
    assertThat(qualifiedTableLocation)
        .as("Table location must be owned by the test metastore")
        .isEqualTo(expectedTableLocation);
    if (fs.exists(qualifiedTableLocation)) {
      assertThat(fs.delete(qualifiedTableLocation, true))
          .as("Failed to delete test table location %s", qualifiedTableLocation)
          .isTrue();
    }
  }

  @TestTemplate
  public void testSelect() {
    List<Object[]> expected =
        ImmutableList.of(row(1L, "a", 1.0F), row(2L, "b", 2.0F), row(3L, "c", Float.NaN));

    assertEquals("Should return all expected rows", expected, sql("SELECT * FROM %s", tableName));
  }

  private static List<DataFile> currentDataFiles(Table table) {
    return Streams.stream(table.newScan().planFiles())
        .map(FileScanTask::file)
        .collect(Collectors.toList());
  }

  private static List<FileScanTask> planSnapshot(Table table, long snapshotId) throws IOException {
    try (CloseableIterable<FileScanTask> tasks =
        table.newScan().useSnapshot(snapshotId).planFiles()) {
      return ImmutableList.copyOf(tasks);
    }
  }

  private static void assertSnapshotHasEncryptionKeys(Table table, Snapshot snapshot) {
    assertThat(snapshot.keyId()).as("manifest list key ID").isNotNull();
    TableMetadata metadata = ((HasTableOperations) table).operations().current();
    EncryptedKey manifestListKey =
        metadata.encryptionKeys().stream()
            .filter(key -> key.keyId().equals(snapshot.keyId()))
            .findFirst()
            .orElse(null);
    assertThat(manifestListKey).as("manifest list key").isNotNull();
    assertThat(metadata.encryptionKeys())
        .as("key encryption key")
        .anyMatch(key -> key.keyId().equals(manifestListKey.encryptedById()));
  }

  @TestTemplate
  public void testRefresh() {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);

    assertThat(currentDataFiles(table)).isNotEmpty();

    sql("INSERT INTO %s VALUES (4, 'd', 4.0), (5, 'e', 5.0), (6, 'f', float('NaN'))", tableName);

    table.refresh();
    assertThat(currentDataFiles(table)).isNotEmpty();
  }

  @TestTemplate
  public void testAppendTransaction() {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);

    List<DataFile> dataFiles = currentDataFiles(table);
    Transaction transaction = table.newTransaction();
    AppendFiles append = transaction.newAppend();

    // add an arbitrary datafile
    append.appendFile(dataFiles.get(0));
    append.commit();
    transaction.commitTransaction();

    assertThat(currentDataFiles(table)).hasSize(dataFiles.size() + 1);
  }

  @TestTemplate
  public void testConcurrentAppendTransactions() {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);

    List<DataFile> dataFiles = currentDataFiles(table);
    Transaction transaction = table.newTransaction();
    AppendFiles append = transaction.newAppend();

    // add an arbitrary datafile
    append.appendFile(dataFiles.get(0));

    // append to the table in the meantime. use a separate load to avoid shared operations
    validationCatalog.loadTable(tableIdent).newFastAppend().appendFile(dataFiles.get(0)).commit();

    append.commit();
    transaction.commitTransaction();

    assertThat(currentDataFiles(table)).hasSize(dataFiles.size() + 2);
  }

  @TestTemplate
  void concurrentAppendsPreserveManifestListKeys() throws Exception {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table table = validationCatalog.loadTable(tableIdent);
    List<DataFile> initialFiles = currentDataFiles(table);
    int initialSnapshotCount = (int) Streams.stream(table.snapshots()).count();

    CoordinatedKMS.blockNextTwoUnwraps();
    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      Future<?> firstAppend =
          executor.submit(() -> table.newFastAppend().appendFile(initialFiles.get(0)).commit());
      awaitUnwrapOrAppendFailure(firstAppend, CoordinatedKMS::awaitFirstUnwrap);

      Future<?> secondAppend =
          executor.submit(() -> table.newFastAppend().appendFile(initialFiles.get(0)).commit());
      awaitUnwrapOrAppendFailure(secondAppend, CoordinatedKMS::awaitSecondUnwrap);

      // The second refresh replaced the shared manager while the first writer still owns the old
      // one.
      CoordinatedKMS.releaseFirstUnwrap();
      firstAppend.get(INTERLEAVING_TIMEOUT_SECONDS, TimeUnit.SECONDS);

      CoordinatedKMS.releaseSecondUnwrap();
      secondAppend.get(INTERLEAVING_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    } finally {
      CoordinatedKMS.reset();
      executor.shutdownNow();
      assertThat(executor.awaitTermination(INTERLEAVING_TIMEOUT_SECONDS, TimeUnit.SECONDS))
          .isTrue();
    }

    validationCatalog.invalidateTable(tableIdent);
    Table reloaded = validationCatalog.loadTable(tableIdent);
    assertThat(reloaded.snapshots()).hasSize(initialSnapshotCount + 2);
    for (Snapshot snapshot : reloaded.snapshots()) {
      assertSnapshotHasEncryptionKeys(reloaded, snapshot);
      assertThat(planSnapshot(reloaded, snapshot.snapshotId())).isNotEmpty();
    }
  }

  private static void awaitUnwrapOrAppendFailure(Future<?> append, Runnable awaitUnwrap)
      throws Exception {
    try {
      awaitUnwrap.run();
    } catch (AssertionError e) {
      if (append.isDone()) {
        append.get();
      }

      throw e;
    }
  }

  // See CatalogTests#testConcurrentReplaceTransactions
  @TestTemplate
  public void testConcurrentReplaceTransactions() {
    validationCatalog.initialize(catalogName, catalogConfig);

    Table table = validationCatalog.loadTable(tableIdent);
    DataFile file = currentDataFiles(table).get(0);
    Schema schema = table.schema();

    // Write data for a replace transaction that will be committed later
    Transaction secondReplace =
        validationCatalog
            .buildTable(tableIdent, schema)
            .withProperty("encryption.key-id", UnitestKMS.MASTER_KEY_NAME1)
            .replaceTransaction();
    secondReplace.newFastAppend().appendFile(file).commit();

    // Commit another replace transaction first
    Transaction firstReplace =
        validationCatalog
            .buildTable(tableIdent, schema)
            .withProperty("encryption.key-id", UnitestKMS.MASTER_KEY_NAME1)
            .replaceTransaction();
    firstReplace.newFastAppend().appendFile(file).commit();
    firstReplace.commitTransaction();

    secondReplace.commitTransaction();

    Table afterSecondReplace = validationCatalog.loadTable(tableIdent);
    assertThat(currentDataFiles(afterSecondReplace)).hasSize(1);
  }

  @TestTemplate
  void invalidDekCreateCleansStagedMetadata() throws IOException {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table original = validationCatalog.loadTable(tableIdent);
    Schema schema = original.schema();
    DataFile file = currentDataFiles(original).get(0);
    assertThat(validationCatalog.dropTable(tableIdent, false)).isTrue();
    Transaction create =
        validationCatalog
            .buildTable(tableIdent, schema)
            .withProperty(TableProperties.FORMAT_VERSION, "3")
            .withProperty(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1)
            .createTransaction();
    create.newFastAppend().appendFile(file).commit();
    Snapshot stagedSnapshot = create.table().currentSnapshot();
    String stagedManifestList = stagedSnapshot.manifestListLocation();
    List<String> stagedManifests =
        stagedSnapshot.allManifests(create.table().io()).stream()
            .map(manifest -> manifest.path())
            .collect(Collectors.toList());
    assertThat(stagedManifests).isNotEmpty();
    create.updateProperties().set(TableProperties.ENCRYPTION_DEK_LENGTH, "17").commit();

    assertThatThrownBy(create::commitTransaction)
        .isInstanceOf(ValidationException.class)
        .hasMessage("Invalid data key length: 17 (must be 16, 24, or 32)");
    assertThat(validationCatalog.tableExists(tableIdent)).isFalse();
    assertThat(localInput(stagedManifestList).exists()).isFalse();
    assertThat(stagedManifests).allSatisfy(path -> assertThat(localInput(path).exists()).isFalse());
  }

  @TestTemplate
  void retainedEncryptedHandleFollowsPlaintextRecreation() throws IOException {
    validationCatalog.initialize(catalogName, catalogConfig);
    Table retained = validationCatalog.loadTable(tableIdent);
    Schema schema = retained.schema();
    assertThat(retained.encryption()).isNotSameAs(PlaintextEncryptionManager.instance());
    assertThat(retained.io()).isInstanceOf(EncryptingFileIO.class);

    assertThat(validationCatalog.dropTable(tableIdent, false)).isTrue();
    assertThatThrownBy(retained::refresh)
        .isInstanceOf(NoSuchTableException.class)
        .hasMessage("No such table: %s", tableIdent);
    assertThat(retained.encryption()).isSameAs(PlaintextEncryptionManager.instance());
    assertThat(retained.io()).isNotInstanceOf(EncryptingFileIO.class);

    Table plaintext =
        validationCatalog
            .buildTable(tableIdent, schema)
            .withProperty(TableProperties.FORMAT_VERSION, "3")
            .create();
    DataFile file =
        DataFiles.builder(plaintext.spec())
            .withPath(plaintext.location() + "/plain-recreated.parquet")
            .withFileSizeInBytes(1)
            .withRecordCount(1)
            .build();

    retained.refresh();
    assertThat(retained.encryption()).isSameAs(PlaintextEncryptionManager.instance());
    assertThat(retained.io()).isNotInstanceOf(EncryptingFileIO.class);
    retained.newFastAppend().appendFile(file).commit();

    validationCatalog.invalidateTable(tableIdent);
    Table reloaded = validationCatalog.loadTable(tableIdent);
    Snapshot snapshot = reloaded.currentSnapshot();
    assertThat(snapshot).isNotNull();
    assertThat(planSnapshot(reloaded, snapshot.snapshotId())).isNotEmpty();
    assertThat(snapshot.keyId()).isNull();
  }

  @TestTemplate
  public void testInsertAndDelete() {
    sql("INSERT INTO %s VALUES (4, 'd', 4.0), (5, 'e', 5.0), (6, 'f', float('NaN'))", tableName);

    List<Object[]> expected =
        ImmutableList.of(
            row(1L, "a", 1.0F),
            row(2L, "b", 2.0F),
            row(3L, "c", Float.NaN),
            row(4L, "d", 4.0F),
            row(5L, "e", 5.0F),
            row(6L, "f", Float.NaN));

    assertEquals(
        "Should return all expected rows",
        expected,
        sql("SELECT * FROM %s ORDER BY id", tableName));

    sql("DELETE FROM %s WHERE id < 4", tableName);

    expected = ImmutableList.of(row(4L, "d", 4.0F), row(5L, "e", 5.0F), row(6L, "f", Float.NaN));

    assertEquals(
        "Should return all expected rows",
        expected,
        sql("SELECT * FROM %s ORDER BY id", tableName));
  }

  @TestTemplate
  public void testMetadataTamperproofing() throws IOException {
    ChecksumFileSystem fs = ((ChecksumFileSystem) FileSystem.newInstance(new Configuration()));
    catalog.initialize(catalogName, catalogConfig);

    Table table = catalog.loadTable(tableIdent);
    TableMetadata currentMetadata = ((HasTableOperations) table).operations().current();
    Path metadataFile = new Path(currentMetadata.metadataFileLocation());
    Path previousMetadataFile = new Path(Iterables.firstOf(currentMetadata.previousFiles()).file());

    // manual FS tampering: replacing the current metadata file with a previous one
    Path crcPath = fs.getChecksumFile(metadataFile);
    fs.delete(crcPath, false);
    fs.delete(metadataFile, false);
    fs.rename(previousMetadataFile, metadataFile);

    assertThatThrownBy(() -> catalog.loadTable(tableIdent))
        .hasMessageContaining(
            String.format(
                "The current metadata file %s might have been modified. Hash of metadata loaded from storage differs from HMS-stored metadata hash.",
                metadataFile));
  }

  @TestTemplate
  public void testKeyDelete() {
    assertThatThrownBy(
            () -> sql("ALTER TABLE %s UNSET TBLPROPERTIES (`encryption.key-id`)", tableName))
        .isInstanceOf(SparkException.class)
        .hasMessage("Unsupported table change: Cannot remove key ID from an encrypted table");
  }

  @TestTemplate
  public void testKeyAlter() {
    assertThatThrownBy(
            () -> sql("ALTER TABLE %s SET TBLPROPERTIES ('encryption.key-id'='abcd')", tableName))
        .isInstanceOf(SparkException.class)
        .hasMessage("Unsupported table change: Cannot modify key ID of an encrypted table");
  }

  @TestTemplate
  public void testReplaceKeyChange() {
    // Replacing a table with a different encryption key is disallowed
    assertThatThrownBy(
            () ->
                sql(
                    "REPLACE TABLE %s (id bigint) USING iceberg TBLPROPERTIES ('encryption.key-id'='%s')",
                    tableName, UnitestKMS.MASTER_KEY_NAME2))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot modify key ID of an encrypted table");
  }

  @TestTemplate
  public void testDirectDataFileRead() {
    List<Object[]> dataFileTable =
        sql("SELECT file_path FROM %s.%s", tableName, MetadataTableType.ALL_DATA_FILES);
    List<String> dataFiles =
        Streams.concat(dataFileTable.stream())
            .map(row -> (String) row[0])
            .collect(Collectors.toList());

    if (dataFiles.isEmpty()) {
      throw new RuntimeException("No data files found for table " + tableName);
    }

    Schema schema = new Schema(optional(0, "id", Types.IntegerType.get()));
    for (String filePath : dataFiles) {
      assertThatThrownBy(
              () ->
                  Parquet.read(localInput(filePath))
                      .project(schema)
                      .callInit()
                      .build()
                      .iterator()
                      .next())
          .isInstanceOf(ParquetCryptoRuntimeException.class)
          .hasMessageContaining("Trying to read file with encrypted footer. No keys available");
    }
  }

  @TestTemplate
  public void testManifestEncryption() throws IOException {
    List<Object[]> manifestFileTable =
        sql("SELECT path FROM %s.%s", tableName, MetadataTableType.MANIFESTS);

    List<String> manifestFiles =
        Streams.concat(manifestFileTable.stream())
            .map(row -> (String) row[0])
            .collect(Collectors.toList());

    if (manifestFiles.isEmpty()) {
      throw new RuntimeException("No manifest files found for table " + tableName);
    }

    String metadataFolderPath = null;

    // Check encryption of manifest files
    for (String manifestFilePath : manifestFiles) {
      checkMetadataFileEncryption(localInput(manifestFilePath));

      if (metadataFolderPath == null) {
        metadataFolderPath = new File(manifestFilePath).getParent().replaceFirst("file:", "");
      }
    }

    if (metadataFolderPath == null) {
      throw new RuntimeException("No metadata folder found for table " + tableName);
    }

    // Find manifest list and metadata files; check their encryption
    File[] listOfMetadataFiles = new File(metadataFolderPath).listFiles();
    boolean foundManifestListFile = false;

    for (File metadataFile : listOfMetadataFiles) {
      if (metadataFile.getName().startsWith("snap-")) {
        foundManifestListFile = true;
        checkMetadataFileEncryption(localInput(metadataFile));
      }
    }

    if (!foundManifestListFile) {
      throw new RuntimeException("No manifest list files found for table " + tableName);
    }
  }

  @TestTemplate
  public void testDropTableWithPurge() {
    List<Object[]> dataFileTable =
        sql("SELECT file_path FROM %s.%s", tableName, MetadataTableType.ALL_DATA_FILES);
    List<String> dataFiles =
        Streams.concat(dataFileTable.stream())
            .map(row -> (String) row[0])
            .collect(Collectors.toList());
    assertThat(dataFiles).isNotEmpty();
    assertThat(dataFiles)
        .allSatisfy(filePath -> assertThat(localInput(filePath).exists()).isTrue());

    sql("DROP TABLE %s PURGE", tableName);

    assertThat(catalog.tableExists(tableIdent)).as("Table should not exist").isFalse();
    assertThat(dataFiles)
        .allSatisfy(filePath -> assertThat(localInput(filePath).exists()).isFalse());
  }

  private void checkMetadataFileEncryption(InputFile file) throws IOException {
    SeekableInputStream stream = file.newStream();
    byte[] magic = new byte[4];
    stream.read(magic);
    stream.close();
    assertThat(magic).isEqualTo(Ciphers.GCM_STREAM_MAGIC_STRING.getBytes(StandardCharsets.UTF_8));
  }

  public static class CoordinatedKMS extends UnitestKMS {
    private static volatile UnwrapInterleaving interleaving;

    static void blockNextTwoUnwraps() {
      if (interleaving != null) {
        throw new IllegalStateException("An unwrap interleaving is already active");
      }

      interleaving = new UnwrapInterleaving();
    }

    static void awaitFirstUnwrap() {
      currentInterleaving().awaitFirstUnwrap();
    }

    static void awaitSecondUnwrap() {
      currentInterleaving().awaitSecondUnwrap();
    }

    static void releaseFirstUnwrap() {
      currentInterleaving().releaseFirstUnwrap();
    }

    static void releaseSecondUnwrap() {
      currentInterleaving().releaseSecondUnwrap();
    }

    static void reset() {
      UnwrapInterleaving current = interleaving;
      if (current != null) {
        current.releaseFirstUnwrap();
        current.releaseSecondUnwrap();
        interleaving = null;
      }
    }

    @Override
    public ByteBuffer unwrapKey(ByteBuffer wrappedKey, String wrappingKeyId) {
      UnwrapInterleaving current = interleaving;
      if (current != null) {
        current.blockNextUnwrap();
      }

      return super.unwrapKey(wrappedKey, wrappingKeyId);
    }

    private static UnwrapInterleaving currentInterleaving() {
      UnwrapInterleaving current = interleaving;
      if (current == null) {
        throw new IllegalStateException("No unwrap interleaving is active");
      }

      return current;
    }
  }

  private static class UnwrapInterleaving {
    private final AtomicInteger unwrapCalls = new AtomicInteger();
    private final CountDownLatch firstUnwrapEntered = new CountDownLatch(1);
    private final CountDownLatch releaseFirstUnwrap = new CountDownLatch(1);
    private final CountDownLatch secondUnwrapEntered = new CountDownLatch(1);
    private final CountDownLatch releaseSecondUnwrap = new CountDownLatch(1);

    private void blockNextUnwrap() {
      int call = unwrapCalls.incrementAndGet();
      if (call == 1) {
        firstUnwrapEntered.countDown();
        await(releaseFirstUnwrap, "release the first key unwrap");
      } else if (call == 2) {
        secondUnwrapEntered.countDown();
        await(releaseSecondUnwrap, "release the second key unwrap");
      }
    }

    private void awaitFirstUnwrap() {
      await(firstUnwrapEntered, "the first key unwrap");
    }

    private void awaitSecondUnwrap() {
      await(secondUnwrapEntered, "the second key unwrap");
    }

    private void releaseFirstUnwrap() {
      releaseFirstUnwrap.countDown();
    }

    private void releaseSecondUnwrap() {
      releaseSecondUnwrap.countDown();
    }

    private static void await(CountDownLatch latch, String action) {
      try {
        if (!latch.await(INTERLEAVING_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
          throw new AssertionError("Timed out waiting for " + action);
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError("Interrupted while waiting for " + action, e);
      }
    }
  }
}
