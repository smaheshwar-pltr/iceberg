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

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.iceberg.TableProperties;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.io.SeekableInputStream;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.relocated.com.google.common.collect.Iterables;
import org.apache.iceberg.relocated.com.google.common.collect.Maps;
import org.apache.iceberg.util.ByteBuffers;
import org.apache.iceberg.util.SerializableMap;

public class StandardEncryptionManager implements EncryptionManager {
  // Preserve the UID used by released 1.11.0 managers so existing serialized instances load.
  private static final long serialVersionUID = -5497522897222558303L;

  // Maximal lifespan of key encryption keys is 2 years according to NIST SP 800-57 (PART 1 REV. 5,
  // section 5.3.6.7.b)
  private static final long KEY_ENCRYPTION_KEY_LIFESPAN_MS = TimeUnit.DAYS.toMillis(730);
  static final String KEY_TIMESTAMP = "KEY_TIMESTAMP";

  private final String tableKeyId;
  private final int dataKeyLength;
  private final KeyManagementClient kmsClient;
  private volatile Map<String, EncryptedKey> encryptionKeys;

  // used in key encryption key rotation unitests
  private long testTimeShift;

  private transient volatile LoadingCache<String, ByteBuffer> unwrappedKeyCache;
  private transient volatile SecureRandom lazyRNG = null;

  /**
   * @param keys encryption keys from table metadata
   * @param tableKeyId table encryption key id
   * @param dataKeyLength length of data encryption key (16/24/32 bytes)
   * @param kmsClient Client of KMS used to wrap/unwrap keys in envelope encryption
   */
  public StandardEncryptionManager(
      List<EncryptedKey> keys,
      String tableKeyId,
      int dataKeyLength,
      KeyManagementClient kmsClient) {
    Preconditions.checkNotNull(tableKeyId, "Invalid encryption key ID: null");
    Preconditions.checkArgument(
        dataKeyLength == 16 || dataKeyLength == 24 || dataKeyLength == 32,
        "Invalid data key length: %s (must be 16, 24, or 32)",
        dataKeyLength);
    Preconditions.checkNotNull(kmsClient, "Invalid KMS client: null");
    this.tableKeyId = tableKeyId;
    this.kmsClient = kmsClient;
    this.dataKeyLength = dataKeyLength;
    this.testTimeShift = 0;

    Map<String, EncryptedKey> initialKeys = Maps.newLinkedHashMap();
    if (keys != null) {
      for (EncryptedKey key : keys) {
        initialKeys.put(key.keyId(), copyKey(key));
      }
    }

    this.encryptionKeys = SerializableMap.copyOf(initialKeys);
  }

  @Override
  public NativeEncryptionOutputFile encrypt(OutputFile plainOutput) {
    return new StandardEncryptedOutputFile(plainOutput, dataKeyLength);
  }

  @Override
  public NativeEncryptionInputFile decrypt(EncryptedInputFile encrypted) {
    // this input file will lazily parse key metadata in case the file is not an AES GCM stream.
    if (encrypted instanceof NativeEncryptionInputFile) {
      return (NativeEncryptionInputFile) encrypted;
    }

    return new StandardDecryptedInputFile(encrypted);
  }

  @Override
  public Iterable<InputFile> decrypt(Iterable<EncryptedInputFile> encrypted) {
    return Iterables.transform(encrypted, this::decrypt);
  }

  private LoadingCache<String, ByteBuffer> unwrappedKeyCache() {
    if (this.unwrappedKeyCache == null) {
      this.unwrappedKeyCache =
          Caffeine.newBuilder()
              .expireAfterWrite(1, TimeUnit.HOURS)
              .build(
                  keyId ->
                      kmsClient.unwrapKey(
                          encryptionKeys.get(keyId).encryptedKeyMetadata(), tableKeyId));
    }

    return unwrappedKeyCache;
  }

  private SecureRandom workerRNG() {
    if (this.lazyRNG == null) {
      this.lazyRNG = new SecureRandom();
    }

    return lazyRNG;
  }

  Map<String, EncryptedKey> encryptionKeys() {
    return encryptionKeys;
  }

  Map<String, EncryptedKey> copyEncryptionKeys() {
    Map<String, EncryptedKey> snapshot = Maps.newLinkedHashMap();
    encryptionKeys.forEach((keyId, key) -> snapshot.put(keyId, copyKey(key)));
    return snapshot;
  }

  String keyEncryptionKeyID() {
    EncryptedKey existingKey = findUnexpiredKeyEncryptionKey();
    if (existingKey != null) {
      return existingKey.keyId();
    }

    ByteBuffer unwrapped = newKey();
    EncryptedKey key = newKeyEncryptionKey(unwrapped);
    unwrappedKeyCache().put(key.keyId(), unwrapped);
    publishKeys(key);

    return key.keyId();
  }

  private EncryptedKey findUnexpiredKeyEncryptionKey() {
    Map<String, EncryptedKey> registry = encryptionKeys;
    for (EncryptedKey key : registry.values()) {
      if (key.encryptedById().equals(tableKeyId)) {
        String timestampProperty = key.properties().get(KEY_TIMESTAMP);
        long keyTimestamp = Long.parseLong(timestampProperty);
        if (currentTimeMillis() - keyTimestamp < KEY_ENCRYPTION_KEY_LIFESPAN_MS) {
          return key;
        }
      }
    }

    return null;
  }

  // For key rotation tests
  void setTestTimeShift(long shift) {
    testTimeShift = shift;
  }

  private long currentTimeMillis() {
    return System.currentTimeMillis() + testTimeShift;
  }

  ByteBuffer encryptedByKey(String manifestListKeyID) {
    EncryptedKey encryptedKeyMetadata = encryptionKeys.get(manifestListKeyID);

    Preconditions.checkState(
        encryptedKeyMetadata != null,
        "Cannot find manifest list key metadata with id %s",
        manifestListKeyID);

    Preconditions.checkArgument(
        !encryptedKeyMetadata.encryptedById().equals(tableKeyId),
        "%s is a key encryption key, not manifest list key metadata",
        manifestListKeyID);

    return unwrappedKeyCache().get(encryptedKeyMetadata.encryptedById());
  }

  public String addManifestListKeyMetadata(NativeEncryptionKeyMetadata keyMetadata) {
    String manifestListKeyID = generateKeyId();
    EncryptedKey keyEncryptionKey = findUnexpiredKeyEncryptionKey();
    ByteBuffer unwrappedKey;
    boolean publishKeyEncryptionKey = false;
    if (keyEncryptionKey != null) {
      unwrappedKey = unwrappedKeyCache().get(keyEncryptionKey.keyId());
    } else {
      unwrappedKey = newKey();
      keyEncryptionKey = newKeyEncryptionKey(unwrappedKey);
      unwrappedKeyCache().put(keyEncryptionKey.keyId(), unwrappedKey);
      publishKeyEncryptionKey = true;
    }

    String keyEncryptionKeyTimestamp = keyEncryptionKey.properties().get(KEY_TIMESTAMP);
    ByteBuffer encryptedKeyMetadata =
        EncryptionUtil.encryptManifestListKeyMetadata(
            unwrappedKey, keyEncryptionKeyTimestamp, keyMetadata);
    EncryptedKey manifestListKey =
        new BaseEncryptedKey(
            manifestListKeyID, encryptedKeyMetadata, keyEncryptionKey.keyId(), null);

    if (publishKeyEncryptionKey) {
      publishKeys(keyEncryptionKey, manifestListKey);
    } else {
      publishKeys(manifestListKey);
    }

    return manifestListKeyID;
  }

  private EncryptedKey newKeyEncryptionKey(ByteBuffer unwrappedKey) {
    ByteBuffer wrapped = kmsClient.wrapKey(unwrappedKey, tableKeyId);
    Map<String, String> properties = Maps.newHashMap();
    properties.put(KEY_TIMESTAMP, "" + currentTimeMillis());
    return new BaseEncryptedKey(generateKeyId(), wrapped, tableKeyId, properties);
  }

  private synchronized void publishKeys(EncryptedKey... keys) {
    Map<String, EncryptedKey> updated = SerializableMap.copyOf(encryptionKeys);
    for (EncryptedKey key : keys) {
      updated.put(key.keyId(), key);
    }

    this.encryptionKeys = updated;
  }

  private String generateKeyId() {
    byte[] idBytes = new byte[16];
    workerRNG().nextBytes(idBytes);
    return Base64.getEncoder().encodeToString(idBytes);
  }

  private ByteBuffer newKey() {
    byte[] newKey = new byte[dataKeyLength];
    workerRNG().nextBytes(newKey);
    return ByteBuffer.wrap(newKey);
  }

  private static EncryptedKey copyKey(EncryptedKey key) {
    return new BaseEncryptedKey(
        key.keyId(),
        ByteBuffers.copy(key.encryptedKeyMetadata()),
        key.encryptedById(),
        key.properties());
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

    @Override
    public OutputFile encryptingOutputFile() {
      if (null == lazyEncryptingOutputFile) {
        this.lazyEncryptingOutputFile =
            new AesGcmOutputFile(
                plainOutputFile,
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
      if (null == lazyKeyMetadata) {
        this.lazyKeyMetadata = StandardKeyMetadata.castOrParse(encryptedInputFile.keyMetadata());
      }

      return lazyKeyMetadata;
    }

    private AesGcmInputFile decrypted() {
      if (null == lazyDecryptedInputFile) {
        this.lazyDecryptedInputFile =
            new AesGcmInputFile(
                encryptedInputFile.encryptedInputFile(),
                ByteBuffers.toByteArray(keyMetadata().encryptionKey()),
                ByteBuffers.toByteArray(keyMetadata().aadPrefix()),
                keyMetadata().fileLength());
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
}
