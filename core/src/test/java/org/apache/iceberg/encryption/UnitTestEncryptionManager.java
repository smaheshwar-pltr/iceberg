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
import java.util.Arrays;
import java.util.List;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.io.SeekableInputStream;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableList;
import org.apache.iceberg.util.ByteBuffers;

// Extension is required since Iceberg `instanceof` checks `EncryptionManager`s with
// `StandardEncryptionManager`.
public class UnitTestEncryptionManager extends StandardEncryptionManager {

  private final KeyMetadataWrapper wrapper = new UnitTestKeyMetadataWrapper();

  @SuppressWarnings("unused")
  public UnitTestEncryptionManager() {
    this("keyA", 16, ImmutableList.of(), new UnitestKMS());
  }

  public UnitTestEncryptionManager(
      String tableKeyId,
      int dataKeyLength,
      List<WrappedEncryptionKey> keys,
      KeyManagementClient kmsClient) {
    super(tableKeyId, dataKeyLength, keys, kmsClient);
  }

  @Override
  public NativeEncryptionOutputFile encrypt(OutputFile plainOutput) {
    return new WrappingOutputFile(super.encrypt(plainOutput));
  }

  @Override
  public NativeEncryptionInputFile decrypt(EncryptedInputFile encrypted) {
    return new UnwrappingInputFile(super.decrypt(encrypted));
  }

  private class WrappingOutputFile implements NativeEncryptionOutputFile {
    private final NativeEncryptionOutputFile delegate;
    private OutputFile lazyEncryptingOutputFile = null;

    private WrappingOutputFile(NativeEncryptionOutputFile delegate) {
      this.delegate = delegate;
    }

    @Override
    public OutputFile encryptingOutputFile() {
      if (lazyEncryptingOutputFile == null) {
        this.lazyEncryptingOutputFile =
            new AesGcmOutputFile(
                delegate.plainOutputFile(),
                ByteBuffers.toByteArray(
                    wrapper.wrap(
                        delegate.keyMetadata().encryptionKey(), delegate.plainOutputFile())),
                ByteBuffers.toByteArray(
                    wrapper.wrap(delegate.keyMetadata().aadPrefix(), delegate.plainOutputFile())));
      }

      return lazyEncryptingOutputFile;
    }

    @Override
    public NativeEncryptionKeyMetadata keyMetadata() {
      // TODO: Is it really fine for this to differ from what was used in encryptingOutputFile?
      return delegate.keyMetadata();
    }

    @Override
    public OutputFile plainOutputFile() {
      return delegate.plainOutputFile();
    }
  }

  public class UnwrappingInputFile implements NativeEncryptionInputFile {
    private final NativeEncryptionInputFile delegate;
    private AesGcmInputFile lazyDecryptingInputFile = null;

    private UnwrappingInputFile(NativeEncryptionInputFile delegate) {
      this.delegate = delegate;
    }

    private AesGcmInputFile decrypted() {
      if (lazyDecryptingInputFile == null) {
        this.lazyDecryptingInputFile =
            new AesGcmInputFile(
                delegate.encryptedInputFile(),
                ByteBuffers.toByteArray(
                    wrapper.unwrap(
                        delegate.keyMetadata().encryptionKey(), delegate.encryptedInputFile())),
                ByteBuffers.toByteArray(
                    wrapper.unwrap(
                        delegate.keyMetadata().aadPrefix(), delegate.encryptedInputFile())));
      }

      return lazyDecryptingInputFile;
    }

    @Override
    public InputFile encryptedInputFile() {
      return delegate.encryptedInputFile();
    }

    @Override
    public NativeEncryptionKeyMetadata keyMetadata() {
      // TODO: Is it really fine for this to differ from what was used in decrypted?
      return delegate.keyMetadata();
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
    ByteBuffer wrap(ByteBuffer key, OutputFile outputFile);

    ByteBuffer unwrap(ByteBuffer wrappedKey, InputFile inputFile);
  }

  // NB: Not for production use. Uses file's location to encrypt/decrypt.
  private static class UnitTestKeyMetadataWrapper implements KeyMetadataWrapper, Serializable {

    private static final int KEK_LENGTH = 16;

    public ByteBuffer wrap(ByteBuffer key, OutputFile outputFile) {
      Ciphers.AesGcmEncryptor keyEncryptor = new Ciphers.AesGcmEncryptor(getKek(outputFile.location()));
      byte[] encryptedKey = keyEncryptor.encrypt(ByteBuffers.toByteArray(key), null);
//      return ByteBuffer.wrap(encryptedKey);
      return ByteBuffer.wrap(truncateKey(encryptedKey));
    }

    public ByteBuffer unwrap(ByteBuffer wrappedKey, InputFile inputFile) {
      Ciphers.AesGcmDecryptor keyDecryptor = new Ciphers.AesGcmDecryptor(getKek(inputFile.location()));
      byte[] key = keyDecryptor.decrypt(ByteBuffers.toByteArray(wrappedKey), null);
//      return ByteBuffer.wrap(key);
      return ByteBuffer.wrap(truncateKey(key));
    }

    private static byte[] getKek(String location) {
      return truncateKey(location.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] truncateKey(byte[] key) {
      return Arrays.copyOf(key, KEK_LENGTH);
    }
  }
}
