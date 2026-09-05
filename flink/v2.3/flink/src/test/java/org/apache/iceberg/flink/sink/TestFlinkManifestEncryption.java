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
package org.apache.iceberg.flink.sink;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.CatalogUtil;
import org.apache.iceberg.DataFile;
import org.apache.iceberg.DataFiles;
import org.apache.iceberg.FileFormat;
import org.apache.iceberg.ManifestFile;
import org.apache.iceberg.PartitionSpec;
import org.apache.iceberg.Table;
import org.apache.iceberg.TableProperties;
import org.apache.iceberg.TableUtil;
import org.apache.iceberg.catalog.Namespace;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.encryption.Ciphers;
import org.apache.iceberg.encryption.NativeEncryptionOutputFile;
import org.apache.iceberg.encryption.StandardEncryptionManager;
import org.apache.iceberg.encryption.UnitestKMS;
import org.apache.iceberg.flink.SimpleDataUtil;
import org.apache.iceberg.hadoop.HadoopFileIO;
import org.apache.iceberg.hive.HiveCatalog;
import org.apache.iceberg.hive.TestHiveMetastore;
import org.apache.iceberg.io.FileIO;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.io.OutputFileFactory;
import org.apache.iceberg.io.PositionOutputStream;
import org.apache.iceberg.io.WriteResult;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableMap;
import org.apache.iceberg.util.ByteBuffers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Covers Flink's rejection of encrypted tables, and the plaintext-manifest defect that motivates
 * it, against real {@link StandardEncryptionManager} tables loaded from a Hive catalog. Encryption
 * is only wired through {@code HiveTableOperations#encryption()} today, so the Hive metastore is
 * the only way to obtain a table whose {@code encryption()} is not a plaintext manager.
 */
public class TestFlinkManifestEncryption {

  private static final String AVRO_MAGIC = "Obj";
  private static final Namespace NAMESPACE = Namespace.of("flink_manifest_encryption");
  private static final TableIdentifier ENCRYPTED = TableIdentifier.of(NAMESPACE, "encrypted");
  private static final TableIdentifier PLAINTEXT = TableIdentifier.of(NAMESPACE, "plaintext");

  private static TestHiveMetastore metastore;
  private static HiveConf hiveConf;
  private static HiveCatalog catalog;

  private Table encryptedTable;
  private Table plaintextTable;

  @BeforeAll
  public static void startMetastore() {
    metastore = new TestHiveMetastore();
    metastore.start();
    hiveConf = metastore.hiveConf();
    catalog =
        (HiveCatalog)
            CatalogUtil.loadCatalog(
                HiveCatalog.class.getName(),
                "hive",
                ImmutableMap.of(
                    CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getCanonicalName()),
                hiveConf);
  }

  @AfterAll
  public static void stopMetastore() throws Exception {
    catalog = null;
    metastore.stop();
    metastore = null;
  }

  @BeforeEach
  public void createTables() {
    if (!catalog.namespaceExists(NAMESPACE)) {
      catalog.createNamespace(NAMESPACE);
    }

    encryptedTable =
        catalog.createTable(
            ENCRYPTED,
            SimpleDataUtil.SCHEMA,
            PartitionSpec.unpartitioned(),
            ImmutableMap.of(
                TableProperties.FORMAT_VERSION,
                "3",
                TableProperties.ENCRYPTION_TABLE_KEY,
                UnitestKMS.MASTER_KEY_NAME1));

    plaintextTable =
        catalog.createTable(
            PLAINTEXT,
            SimpleDataUtil.SCHEMA,
            PartitionSpec.unpartitioned(),
            ImmutableMap.of(TableProperties.FORMAT_VERSION, "3"));
  }

  @AfterEach
  public void dropTables() {
    catalog.dropTable(ENCRYPTED, true);
    catalog.dropTable(PLAINTEXT, true);
  }

  /** The encrypted table really is encrypted: no stubbing of {@link Table#encryption()}. */
  @Test
  public void testTablesUnderTest() {
    assertThat(encryptedTable.encryption()).isInstanceOf(StandardEncryptionManager.class);
    assertThat(plaintextTable.encryption()).isNotInstanceOf(StandardEncryptionManager.class);
  }

  /**
   * The defect the guard exists for. {@link FlinkManifestUtil#writeDataFiles} is the unguarded
   * primitive that {@link FlinkManifestUtil#writeCompletedFiles} wraps: it writes a per-checkpoint
   * manifest through the plaintext {@code ManifestFiles.write} overload, and {@code
   * ManifestOutputFileFactory#create} supplies a plain {@link OutputFile} even for an encrypted
   * table, because {@code EncryptingFileIO#newOutputFile(String)} forwards to the wrapped {@link
   * FileIO}. The resulting manifest is a plaintext Avro object container file whose entries still
   * carry each data file's key metadata, so the data encryption key of an encrypted data file is
   * recoverable from it with no key material at all.
   */
  @Test
  public void testCheckpointManifestIsPlaintextAndCarriesDataFileKey() throws IOException {
    NativeEncryptionOutputFile encryptedData = writeEncryptedDataFile();
    byte[] dek = ByteBuffers.toByteArray(encryptedData.keyMetadata().encryptionKey());
    assertThat(dek).hasSize(TableProperties.ENCRYPTION_DEK_LENGTH_DEFAULT);
    DataFile dataFile = asDataFile(encryptedData, encryptedTable);

    // The data file itself is encrypted at rest.
    assertThat(magic(readAll(plainIo(), dataFile.location()), 4))
        .isEqualTo(Ciphers.GCM_STREAM_MAGIC_STRING);

    OutputFile manifestOutputFile = manifestOutputFile("leaky-checkpoint-manifest.avro");
    ManifestFile manifest =
        FlinkManifestUtil.writeDataFiles(
            manifestOutputFile,
            encryptedTable.spec(),
            List.of(dataFile),
            TableUtil.formatVersion(encryptedTable));

    // The manifest listing it is not: it is a plaintext Avro object container file.
    byte[] manifestBytes = readAll(plainIo(), manifest.path());
    assertThat(magic(manifestBytes, 3)).isEqualTo(AVRO_MAGIC);
    assertThat(magic(manifestBytes, 4)).isNotEqualTo(Ciphers.GCM_STREAM_MAGIC_STRING);
    assertThat(manifest.keyMetadata()).isNull();

    // A plain FileIO with no key material reads it back, and the entry still holds the DEK.
    List<DataFile> readBack =
        FlinkManifestUtil.readDataFiles(manifest, plainIo(), encryptedTable.specs());
    assertThat(readBack).hasSize(1);
    ByteBuffer keyMetadata = readBack.get(0).keyMetadata();
    assertThat(keyMetadata).isNotNull();
    assertThat(indexOf(ByteBuffers.toByteArray(keyMetadata), dek)).isGreaterThanOrEqualTo(0);
  }

  @Test
  public void testCreateOutputFileFactoryRejectsEncryptedTable() {
    assertThatThrownBy(
            () ->
                FlinkManifestUtil.createOutputFileFactory(
                    () -> encryptedTable, encryptedTable.properties(), "job", "operator", 1, 1))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Cannot write to an encrypted table with Flink:");

    assertThatThrownBy(
            () ->
                FlinkManifestUtil.createOutputFileFactory(
                    () -> encryptedTable,
                    encryptedTable.properties(),
                    "job",
                    "operator",
                    1,
                    1,
                    "suffix"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Cannot write to an encrypted table with Flink:");
  }

  @Test
  public void testCreateOutputFileFactoryAllowsPlaintextTable() {
    assertThat(
            FlinkManifestUtil.createOutputFileFactory(
                () -> plaintextTable, plaintextTable.properties(), "job", "operator", 1, 1))
        .isNotNull();
  }

  @Test
  public void testWriteCompletedFilesRejectsEncryptedContentFiles() throws IOException {
    DataFile dataFile = asDataFile(writeEncryptedDataFile(), encryptedTable);
    OutputFile manifestOutputFile = manifestOutputFile("rejected-manifest.avro");

    assertThatThrownBy(
            () ->
                FlinkManifestUtil.writeCompletedFiles(
                    WriteResult.builder().addDataFiles(dataFile).build(),
                    () -> manifestOutputFile,
                    encryptedTable.spec(),
                    TableUtil.formatVersion(encryptedTable)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Cannot write an encrypted file to a plaintext Flink manifest:");
  }

  @Test
  public void testWriteCompletedFilesAllowsPlaintextContentFiles() throws IOException {
    DataFile dataFile =
        DataFiles.builder(plaintextTable.spec())
            .withPath(plaintextTable.location() + "/data/plaintext.parquet")
            .withFileSizeInBytes(10)
            .withRecordCount(1)
            .withFormat(FileFormat.PARQUET)
            .build();

    OutputFile manifestOutputFile =
        plaintextTable
            .io()
            .newOutputFile(plaintextTable.location() + "/metadata/plaintext-manifest.avro");
    DeltaManifests deltaManifests =
        FlinkManifestUtil.writeCompletedFiles(
            WriteResult.builder().addDataFiles(dataFile).build(),
            () -> manifestOutputFile,
            plaintextTable.spec(),
            TableUtil.formatVersion(plaintextTable));

    assertThat(magic(readAll(plainIo(), deltaManifests.dataManifest().path()), 3))
        .isEqualTo(AVRO_MAGIC);
  }

  /** Flink's data path is encrypted: {@link OutputFileFactory} reads {@code table.encryption()}. */
  private NativeEncryptionOutputFile writeEncryptedDataFile() throws IOException {
    OutputFileFactory dataFileFactory =
        OutputFileFactory.builderFor(encryptedTable, 1, 1).format(FileFormat.PARQUET).build();
    NativeEncryptionOutputFile encryptedData =
        (NativeEncryptionOutputFile) dataFileFactory.newOutputFile();
    try (PositionOutputStream out = encryptedData.create()) {
      out.write("super-secret-row".getBytes(StandardCharsets.UTF_8));
    }

    return encryptedData;
  }

  private DataFile asDataFile(NativeEncryptionOutputFile encryptedData, Table table)
      throws IOException {
    String location = encryptedData.encryptingOutputFile().location();
    return DataFiles.builder(table.spec())
        .withPath(location)
        .withFileSizeInBytes(readAll(plainIo(), location).length)
        .withRecordCount(1)
        .withFormat(FileFormat.PARQUET)
        .withEncryptionKeyMetadata(encryptedData.keyMetadata())
        .build();
  }

  private OutputFile manifestOutputFile(String name) {
    return plainIo().newOutputFile(encryptedTable.location() + "/metadata/" + name);
  }

  /** A {@link FileIO} with no encryption manager attached, i.e. an attacker's view of storage. */
  private static FileIO plainIo() {
    return new HadoopFileIO(hiveConf);
  }

  private static String magic(byte[] bytes, int length) {
    return new String(bytes, 0, length, StandardCharsets.UTF_8);
  }

  private static int indexOf(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

  private static byte[] readAll(FileIO io, String location) throws IOException {
    try (InputStream in = io.newInputFile(location).newStream()) {
      return in.readAllBytes();
    }
  }
}
