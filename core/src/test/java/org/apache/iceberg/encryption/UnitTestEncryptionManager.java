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

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.apache.iceberg.TableProperties;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.io.SeekableInputStream;
import org.apache.iceberg.util.ByteBuffers;

// Extension is required since Iceberg `instanceof` checks `EncryptionManager`s with
// `StandardEncryptionManager`.
public class UnitTestEncryptionManager implements EncryptionManager {

  private transient volatile SecureRandom lazyRNG = null;
  private final KeyMetadataWrapper wrapper = new UnitTestKeyMetadataWrapper();

  @SuppressWarnings("unused")
  public UnitTestEncryptionManager() {}

  @Override
  public NativeEncryptionOutputFile encrypt(OutputFile plainOutput) {
    return new StandardEncryptedOutputFile(plainOutput, 16);
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
    private StandardKeyMetadata lazyKeyMetadata = null;
    private OutputFile lazyEncryptingOutputFile = null;

    StandardEncryptedOutputFile(OutputFile plainOutputFile, int dataKeyLength) {
      this.plainOutputFile = plainOutputFile;
      this.dataKeyLength = dataKeyLength;
    }

    @Override
    public StandardKeyMetadata keyMetadata() {
      // TODO: Is it really fine for this to differ from what was used in encryptingOutputFile?
      if (null == lazyKeyMetadata) {
        byte[] fileDek = new byte[dataKeyLength];
        workerRNG().nextBytes(fileDek);

        byte[] aadPrefix = new byte[TableProperties.ENCRYPTION_AAD_LENGTH_DEFAULT];
        workerRNG().nextBytes(aadPrefix);

        this.lazyKeyMetadata = new StandardKeyMetadata(fileDek, aadPrefix);
      }

      return lazyKeyMetadata;
    }

    @Override
    public OutputFile encryptingOutputFile() {
      if (lazyEncryptingOutputFile == null) {
        this.lazyEncryptingOutputFile =
                new AesGcmOutputFile(
                        plainOutputFile(),
                        ByteBuffers.toByteArray(
                                wrapper.wrap(
                                        keyMetadata().encryptionKey(), plainOutputFile().location())),
                        ByteBuffers.toByteArray(
                                wrapper.wrap(keyMetadata().aadPrefix(), plainOutputFile().location())));
      }

      return lazyEncryptingOutputFile;
    }

    @Override
    public OutputFile plainOutputFile() {
      return plainOutputFile;
    }
  }

  private class StandardDecryptedInputFile implements NativeEncryptionInputFile {
    private final EncryptedInputFile encryptedInputFile;
    private StandardKeyMetadata lazyKeyMetadata = null;
    private AesGcmInputFile lazyDecryptedInputFile = null;

    private StandardDecryptedInputFile(EncryptedInputFile encryptedInputFile) {
      this.encryptedInputFile = encryptedInputFile;
    }

    @Override
    public InputFile encryptedInputFile() {
      return encryptedInputFile.encryptedInputFile();
    }

    @Override
    public StandardKeyMetadata keyMetadata() {
      // TODO: Is it really fine for this to differ from what was used in decrypted?
      if (null == lazyKeyMetadata) {
        this.lazyKeyMetadata = StandardKeyMetadata.castOrParse(encryptedInputFile.keyMetadata());
      }

      return lazyKeyMetadata;
    }

    private AesGcmInputFile decrypted() {
      if (lazyDecryptedInputFile == null) {
        this.lazyDecryptedInputFile =
                new AesGcmInputFile(
                        encryptedInputFile(),
                        ByteBuffers.toByteArray(
                                wrapper.wrap(
                                        keyMetadata().encryptionKey(), encryptedInputFile().location())),
                        ByteBuffers.toByteArray(
                                wrapper.wrap(
                                        keyMetadata().aadPrefix(), encryptedInputFile().location())));
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

  public interface KeyMetadataWrapper {
    ByteBuffer wrap(ByteBuffer key, String location);
//    ByteBuffer unwrap(ByteBuffer wrappedKey, InputFile inputFile);
  }

  // NB: Not for production use. Uses file's location to encrypt/decrypt.
  private static class UnitTestKeyMetadataWrapper implements KeyMetadataWrapper, Serializable {

    private static final int KEK_LENGTH = 16;

    public ByteBuffer wrap(ByteBuffer key, String location) {
      Ciphers.AesGcmEncryptor keyEncryptor = new Ciphers.AesGcmEncryptor(getKek(location));
      byte[] encryptedKey = keyEncryptor.encrypt(ByteBuffers.toByteArray(key), null);
//      return ByteBuffer.wrap(encryptedKey);
      return ByteBuffer.wrap(truncateKey(encryptedKey));
    }

//    public ByteBuffer unwrap(ByteBuffer wrappedKey, InputFile inputFile) {
//      Ciphers.AesGcmDecryptor keyDecryptor = new Ciphers.AesGcmDecryptor(getKek(inputFile.location()));
//      byte[] key = keyDecryptor.decrypt(ByteBuffers.toByteArray(wrappedKey), null);
////      return ByteBuffer.wrap(key);
//      return ByteBuffer.wrap(truncateKey(key));
//    }

    private static byte[] getKek(String location) {
      return truncateKey(location.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] truncateKey(byte[] key) {
      return Arrays.copyOf(key, KEK_LENGTH);
    }
  }
}
