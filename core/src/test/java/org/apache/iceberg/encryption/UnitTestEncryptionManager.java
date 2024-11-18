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
package org.apache.iceberg.encryption;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import org.apache.iceberg.FileFormat;
import org.apache.iceberg.TableProperties;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.io.SeekableInputStream;
import org.apache.iceberg.util.ByteBuffers;

public class UnitTestEncryptionManager implements EncryptionManager {

  private static final int DEFAULT_ENCRYPTION_KEY_LENGTH = 16;
  private static final KeyMetadataWrapper WRAPPER = UnitTestKeyMetadataWrapper.INSTANCE;

  private transient volatile SecureRandom lazyRNG = null;

  @Override
  public NativeEncryptionOutputFile encrypt(OutputFile plainOutput) {
    return new StandardEncryptedOutputFile(plainOutput, DEFAULT_ENCRYPTION_KEY_LENGTH);
  }

  @Override
  public NativeEncryptionInputFile decrypt(EncryptedInputFile encrypted) {
    return new StandardDecryptedInputFile(encrypted);
  }

  private SecureRandom workerRNG() {
    if (this.lazyRNG == null) {
      this.lazyRNG = new SecureRandom();
    }

    return lazyRNG;
  }

  private class StandardEncryptedOutputFile implements NativeEncryptionOutputFile {
    private final OutputFile plainOutputFile;
    private final int dataKeyLength;
    private final boolean isAvroFile;

    private StandardKeyMetadata lazyKeyMetadata = null;
    private OutputFile lazyEncryptingOutputFile = null;

    StandardEncryptedOutputFile(OutputFile plainOutputFile, int dataKeyLength) {
      this.plainOutputFile = plainOutputFile;
      this.dataKeyLength = dataKeyLength;
      this.isAvroFile = isAvroFile(plainOutputFile.location());
    }

    @Override
    public StandardKeyMetadata keyMetadata() {
      if (null == lazyKeyMetadata) {
        byte[] fileDek = new byte[dataKeyLength];
        workerRNG().nextBytes(fileDek);

        byte[] aadPrefix = new byte[TableProperties.ENCRYPTION_AAD_LENGTH_DEFAULT];
        workerRNG().nextBytes(aadPrefix);

        this.lazyKeyMetadata = new StandardKeyMetadata(fileDek, aadPrefix);
      }

      // For Avro files, this method is invoked only to write (persist) the key metadata used
      // to encrypt the file. This key metadata is written into whatever metadata file lies one
      // level above in the Iceberg tree, as per enveloping encryption. So, it is fine only in
      // this case for the value returned by this method to differ from what was used in
      // `encryptingOutputFile()`.
      // For Avro files, the AesGcmOutputFile returned by `encryptingOutputFile()` is used to
      // encrypt
      // and not the `keyMetadata()`, but this doesn't hold for Parquet which uses PME instead.
      // TODO: Everything except for Parquet and Orc instead?
      // TODO: Write note about Avro data files.
      return (isAvroFile
          ? WRAPPER.wrap(lazyKeyMetadata, plainOutputFile.location())
          : lazyKeyMetadata);
    }

    @Override
    public OutputFile encryptingOutputFile() {
      if (lazyEncryptingOutputFile == null) {
        // We need to encrypt with the unwrapped key metadata. First, refresh it:
        keyMetadata();
        this.lazyEncryptingOutputFile =
            new AesGcmOutputFile(
                plainOutputFile(),
                ByteBuffers.toByteArray(lazyKeyMetadata.encryptionKey()),
                ByteBuffers.toByteArray(lazyKeyMetadata.aadPrefix()));
      }

      return lazyEncryptingOutputFile;
    }

    @Override
    public OutputFile plainOutputFile() {
      return plainOutputFile;
    }
  }

  private static class StandardDecryptedInputFile implements NativeEncryptionInputFile {
    private final EncryptedInputFile encryptedInputFile;
    private final boolean isAvroFile;

    private StandardKeyMetadata lazyKeyMetadata = null;
    private AesGcmInputFile lazyDecryptedInputFile = null;

    private StandardDecryptedInputFile(EncryptedInputFile encryptedInputFile) {
      this.encryptedInputFile = encryptedInputFile;
      this.isAvroFile = isAvroFile(encryptedInputFile.encryptedInputFile().location());
    }

    @Override
    public InputFile encryptedInputFile() {
      return encryptedInputFile.encryptedInputFile();
    }

    @Override
    public StandardKeyMetadata keyMetadata() {
      if (null == lazyKeyMetadata) {
        StandardKeyMetadata wrappedMetadata =
            StandardKeyMetadata.castOrParse(encryptedInputFile.keyMetadata());
        // The key metadata of the encryptedInputFile will have been wrapped if it is an Avro file
        // by StandardEncryptedOutputFile#keyMetadata() before being persisted. Unwrap that here:
        this.lazyKeyMetadata =
            isAvroFile
                ? WRAPPER.unwrap(
                    wrappedMetadata, encryptedInputFile.encryptedInputFile().location())
                : wrappedMetadata;
      }

      return lazyKeyMetadata;
    }

    private AesGcmInputFile decrypted() {
      if (lazyDecryptedInputFile == null) {
        this.lazyDecryptedInputFile =
            new AesGcmInputFile(
                encryptedInputFile(),
                ByteBuffers.toByteArray(keyMetadata().encryptionKey()),
                ByteBuffers.toByteArray(keyMetadata().aadPrefix()));
      }

      return lazyDecryptedInputFile;
    }

    @Override
    public long getLength() {
      return decrypted().getLength();
    }

    @Override
    public SeekableInputStream newStream() {
      return decrypted().newStream();
    }

    @Override
    public String location() {
      return decrypted().location();
    }

    @Override
    public boolean exists() {
      return decrypted().exists();
    }
  }

  interface KeyMetadataWrapper {
    StandardKeyMetadata wrap(StandardKeyMetadata keyMetadata, String location);

    StandardKeyMetadata unwrap(StandardKeyMetadata wrappedKeyMetadata, String location);
  }

  // NB: Not for production use. Uses file's location to encrypt/decrypt.
  private enum UnitTestKeyMetadataWrapper implements KeyMetadataWrapper {
    INSTANCE;

    @Override
    public StandardKeyMetadata wrap(StandardKeyMetadata keyMetadata, String location) {
      return new StandardKeyMetadata(
          wrap(keyMetadata.encryptionKey(), location), wrap(keyMetadata.aadPrefix(), location));
    }

    @Override
    public StandardKeyMetadata unwrap(StandardKeyMetadata wrappedKeyMetadata, String location) {
      return new StandardKeyMetadata(
          unwrap(wrappedKeyMetadata.encryptionKey(), location),
          unwrap(wrappedKeyMetadata.aadPrefix(), location));
    }

    private static byte[] wrap(ByteBuffer key, String location) {
      Ciphers.AesGcmEncryptor keyEncryptor =
          new Ciphers.AesGcmEncryptor(getKekFromLocation(location));
      return keyEncryptor.encrypt(ByteBuffers.toByteArray(key), null);
    }

    public static byte[] unwrap(ByteBuffer wrappedKey, String location) {
      Ciphers.AesGcmDecryptor keyDecryptor =
          new Ciphers.AesGcmDecryptor(getKekFromLocation(location));
      return keyDecryptor.decrypt(ByteBuffers.toByteArray(wrappedKey), null);
    }

    private static byte[] getKekFromLocation(String location) {
      return Arrays.copyOf(
          location.getBytes(StandardCharsets.UTF_8), DEFAULT_ENCRYPTION_KEY_LENGTH);
    }
  }

  private static boolean isAvroFile(String location) {
    return Objects.equals(FileFormat.fromFileName(location), FileFormat.AVRO);
  }
}
