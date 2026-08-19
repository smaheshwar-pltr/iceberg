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
import java.util.LinkedHashMap;
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

  // Registry maps and their values are never mutated after publication.
  private volatile Map<String, EncryptedKey> encryptionKeys;

  // used in key encryption key rotation unitests
  private volatile long testTimeShift;

  private transient volatile Object keyCreationLock = new Object();
  private transient volatile LoadingCache<String, ByteBuffer> unwrappedKeyCache;
  private transient volatile SecureRandom lazyRNG = null;

  /**
   * @deprecated will be removed in 1.12.0.
   */
  @Deprecated
  public StandardEncryptionManager(
      String tableKeyId, int dataKeyLength, KeyManagementClient kmsClient) {
    this(List.of(), tableKeyId, dataKeyLength, kmsClient);
  }

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

    Map<String, EncryptedKey> initialKeys = new LinkedHashMap<>();
    if (keys != null) {
      for (EncryptedKey key : keys) {
        initialKeys.put(key.keyId(), copyKey(key));
      }
    }

    this.encryptionKeys = initialKeys;
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
    LoadingCache<String, ByteBuffer> cache = this.unwrappedKeyCache;
    if (cache == null) {
      synchronized (this) {
        cache = this.unwrappedKeyCache;
        if (cache == null) {
          cache =
              Caffeine.newBuilder()
                  .expireAfterWrite(1, TimeUnit.HOURS)
                  .build(
                      keyId ->
                          ByteBuffers.copy(
                              kmsClient.unwrapKey(encryptedKeyMetadata(keyId), tableKeyId)));
          this.unwrappedKeyCache = cache;
        }
      }
    }

    return cache;
  }

  private Object keyCreationLock() {
    Object lock = this.keyCreationLock;
    if (lock == null) {
      synchronized (this) {
        lock = this.keyCreationLock;
        if (lock == null) {
          lock = new Object();
          this.keyCreationLock = lock;
        }
      }
    }

    return lock;
  }

  private SecureRandom workerRNG() {
    SecureRandom random = this.lazyRNG;
    if (random == null) {
      synchronized (this) {
        random = this.lazyRNG;
        if (random == null) {
          random = new SecureRandom();
          this.lazyRNG = random;
        }
      }
    }

    return random;
  }

  /**
   * @deprecated will be removed in 1.12.0.
   */
  @Deprecated
  public ByteBuffer wrapKey(ByteBuffer secretKey) {
    return kmsClient.wrapKey(secretKey, tableKeyId);
  }

  /**
   * @deprecated will be removed in 1.12.0.
   */
  @Deprecated
  public ByteBuffer unwrapKey(ByteBuffer wrappedSecretKey) {
    return kmsClient.unwrapKey(wrappedSecretKey, tableKeyId);
  }

  Map<String, EncryptedKey> encryptionKeys() {
    Map<String, EncryptedKey> snapshot = new LinkedHashMap<>();
    encryptionKeys.forEach((keyId, key) -> snapshot.put(keyId, copyKey(key)));
    return snapshot;
  }

  EncryptedKey encryptionKey(String keyId) {
    EncryptedKey key = encryptionKeys.get(keyId);
    return key != null ? copyKey(key) : null;
  }

  String keyEncryptionKeyID() {
    synchronized (keyCreationLock()) {
      String existingKeyId = findUnexpiredKeyEncryptionKey();
      if (existingKeyId != null) {
        return existingKeyId;
      }

      ByteBuffer unwrapped = newKey();
      ByteBuffer wrapped = kmsClient.wrapKey(ByteBuffers.copy(unwrapped), tableKeyId);
      Map<String, String> properties = Maps.newHashMap();
      properties.put(KEY_TIMESTAMP, "" + currentTimeMillis());
      EncryptedKey key =
          new BaseEncryptedKey(generateKeyId(), ByteBuffers.copy(wrapped), tableKeyId, properties);

      // The new ID is not visible to callers yet, so populate the cache before publishing the
      // stable registry snapshot.
      unwrappedKeyCache().put(key.keyId(), ByteBuffers.copy(unwrapped));
      addEncryptionKey(key);
      return key.keyId();
    }
  }

  private String findUnexpiredKeyEncryptionKey() {
    for (EncryptedKey key : encryptionKeys.values()) {
      if (key.encryptedById().equals(tableKeyId)) {
        String timestampProperty = key.properties().get(KEY_TIMESTAMP);
        long keyTimestamp = Long.parseLong(timestampProperty);
        if (currentTimeMillis() - keyTimestamp < KEY_ENCRYPTION_KEY_LIFESPAN_MS) {
          return key.keyId();
        }
      }
    }

    return null;
  }

  // For key rotation tests
  void setTestTimeShift(long shift) {
    this.testTimeShift = shift;
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

    return unwrappedKey(encryptedKeyMetadata.encryptedById());
  }

  public String addManifestListKeyMetadata(NativeEncryptionKeyMetadata keyMetadata) {
    String manifestListKeyID = generateKeyId();
    String keyEncryptionKeyID = keyEncryptionKeyID();
    EncryptedKey keyEncryptionKey = encryptionKeys.get(keyEncryptionKeyID);
    Preconditions.checkState(
        keyEncryptionKey != null, "Cannot find key encryption key with id %s", keyEncryptionKeyID);
    String keyEncryptionKeyTimestamp = keyEncryptionKey.properties().get(KEY_TIMESTAMP);
    ByteBuffer encryptedKeyMetadata =
        EncryptionUtil.encryptManifestListKeyMetadata(
            unwrappedKey(keyEncryptionKeyID), keyEncryptionKeyTimestamp, keyMetadata);
    BaseEncryptedKey key =
        new BaseEncryptedKey(
            manifestListKeyID, ByteBuffers.copy(encryptedKeyMetadata), keyEncryptionKeyID, null);

    addEncryptionKey(key);
    return manifestListKeyID;
  }

  private synchronized void addEncryptionKey(EncryptedKey key) {
    Map<String, EncryptedKey> updated = new LinkedHashMap<>(encryptionKeys);
    updated.put(key.keyId(), copyKey(key));
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

  private ByteBuffer encryptedKeyMetadata(String keyId) {
    EncryptedKey key = encryptionKeys.get(keyId);
    Preconditions.checkState(key != null, "Cannot find encryption key with id %s", keyId);
    return ByteBuffers.copy(key.encryptedKeyMetadata());
  }

  private ByteBuffer unwrappedKey(String keyId) {
    return ByteBuffers.copy(unwrappedKeyCache().get(keyId));
  }

  private static EncryptedKey copyKey(EncryptedKey key) {
    // BaseEncryptedKey may retain a full heap buffer's backing array, so copy the buffer first.
    // Its constructor already copies the properties map.
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
