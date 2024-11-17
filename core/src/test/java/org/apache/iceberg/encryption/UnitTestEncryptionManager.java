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

  private transient volatile SecureRandom lazyRNG = null;

  @Override
  public NativeEncryptionOutputFile encrypt(OutputFile plainOutput) {
    return new StandardEncryptedOutputFile(plainOutput, 16);
  }

  @Override
  public NativeEncryptionInputFile decrypt(EncryptedInputFile encrypted) {
    // Unwrap only for manifest files.
    return new StandardDecryptedInputFile(encrypted, isManifestFile(encrypted));
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
    private StandardKeyMetadata lazyKeyMetadata = null;
    private OutputFile lazyEncryptingOutputFile = null;

    StandardEncryptedOutputFile(OutputFile plainOutputFile, int dataKeyLength) {
      this.plainOutputFile = plainOutputFile;
      this.dataKeyLength = dataKeyLength;
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

      return lazyKeyMetadata;
    }

    /** Before writing key metadata, wrap it with a key service. */
    @Override
    public EncryptionKeyMetadata keyMetadataToWrite() {
      return UnitTestKeyMetadataWrapper.INSTANCE.wrap(keyMetadata(), plainOutputFile.location());
    }

    @Override
    public OutputFile encryptingOutputFile() {
      if (lazyEncryptingOutputFile == null) {
        this.lazyEncryptingOutputFile =
            new AesGcmOutputFile(
                plainOutputFile(),
                ByteBuffers.toByteArray(keyMetadata().encryptionKey()),
                ByteBuffers.toByteArray(keyMetadata().aadPrefix()));
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
    private final boolean shouldUnwrap;

    private StandardKeyMetadata lazyKeyMetadata = null;
    private AesGcmInputFile lazyDecryptedInputFile = null;

    private StandardDecryptedInputFile(
        EncryptedInputFile encryptedInputFile, boolean shouldUnwrap) {
      this.encryptedInputFile = encryptedInputFile;
      this.shouldUnwrap = shouldUnwrap;
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
        this.lazyKeyMetadata =
            shouldUnwrap
                ? UnitTestKeyMetadataWrapper.INSTANCE.unwrap(
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

    private static final int KEK_LENGTH = 16;

    @Override
    public StandardKeyMetadata wrap(StandardKeyMetadata keyMetadata, String location) {
      return new StandardKeyMetadata(
          wrap(keyMetadata.encryptionKey(), location),
          wrap(keyMetadata.aadPrefix(), location));
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
      return Arrays.copyOf(location.getBytes(StandardCharsets.UTF_8), KEK_LENGTH);
    }
  }

  // TODO: Fix this.
  private static boolean isManifestFile(EncryptedInputFile encrypted) {
    return Objects.equals(
        FileFormat.fromFileName(encrypted.encryptedInputFile().location()), FileFormat.AVRO);
  }
}
