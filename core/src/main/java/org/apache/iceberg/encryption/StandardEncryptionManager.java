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
import java.util.Collections;
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

/**
 * An immutable, metadata-sourced {@link EncryptionManager} for standard (envelope) encryption.
 *
 * <p>The manager holds an immutable snapshot of the encryption keys that live in table metadata
 * ({@code encryption-keys}). It never mutates that key set. Minting a new manifest-list key is a
 * pure operation ({@link #mintManifestListKey}) that <em>returns</em> the created key(s) rather
 * than storing them; the caller ({@code SnapshotProducer}) attaches the returned keys to the
 * metadata it commits, which is the single, authoritative home for keys. Because there is no
 * mutable state, instances are safe to share across concurrent commits without synchronization, and
 * refreshing an operation just builds a new manager from the refreshed metadata.
 */
public class StandardEncryptionManager implements EncryptionManager {
  // Maximal lifespan of key encryption keys is 2 years according to NIST SP 800-57 (PART 1 REV. 5,
  // section 5.3.6.7.b)
  private static final long KEY_ENCRYPTION_KEY_LIFESPAN_MS = TimeUnit.DAYS.toMillis(730);
  static final String KEY_TIMESTAMP = "KEY_TIMESTAMP";

  private final String tableKeyId;
  private final int dataKeyLength;
  // Immutable snapshot of the keys from table metadata. Never mutated after construction, so it is
  // safe to read concurrently and serializes cleanly to Spark executors.
  private final Map<String, EncryptedKey> encryptionKeys;
  private final KeyManagementClient kmsClient;

  // used in key encryption key rotation unittests
  private long testTimeShift;

  // Runtime-only caches, rebuilt after deserialization. The cache unwraps a KEK's metadata via the
  // KMS; it is keyed by KEK id and populated lazily. Marked volatile for safe lock-free lazy init.
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

    Map<String, EncryptedKey> keyMap = Maps.newLinkedHashMap();
    if (keys != null) {
      for (EncryptedKey key : keys) {
        keyMap.put(
            key.keyId(),
            new BaseEncryptedKey(
                key.keyId(), key.encryptedKeyMetadata(), key.encryptedById(), key.properties()));
      }
    }

    // Unmodifiable view over a serializable map: immutable to callers (so the manager's key set
    // cannot be mutated through encryptionKeys()) yet still serializable to Spark executors.
    this.encryptionKeys = Collections.unmodifiableMap(SerializableMap.copyOf(keyMap));
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

  private synchronized LoadingCache<String, ByteBuffer> unwrappedKeyCache() {
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

  private synchronized SecureRandom workerRNG() {
    if (this.lazyRNG == null) {
      this.lazyRNG = new SecureRandom();
    }

    return lazyRNG;
  }

  Map<String, EncryptedKey> encryptionKeys() {
    return encryptionKeys;
  }

  // For key rotation tests
  void setTestTimeShift(long shift) {
    testTimeShift = shift;
  }

  private long currentTimeMillis() {
    return System.currentTimeMillis() + testTimeShift;
  }

  /**
   * Returns the unwrapped bytes of the key encryption key that wrapped the given manifest-list key.
   * Both keys must already be part of this manager's (metadata-sourced) key set.
   */
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

  /**
   * Mints a new manifest-list key for the given key metadata, without storing it.
   *
   * <p>This is a pure operation: it wraps {@code keyMetadata} under an unexpired key encryption key
   * (reusing one from the metadata-sourced key set, or minting a fresh one if none is unexpired)
   * and returns the created key(s). The caller is responsible for persisting the returned keys into
   * table metadata so they survive across processes.
   *
   * @param keyMetadata the manifest-list key metadata to wrap
   * @return the newly minted manifest-list key and, if a new key encryption key was minted to wrap
   *     it, that key encryption key as well
   */
  public MintedKeys mintManifestListKey(NativeEncryptionKeyMetadata keyMetadata) {
    KeyEncryptionKey keyEncryptionKey = keyEncryptionKey();
    String keyEncryptionKeyTimestamp = keyEncryptionKey.key().properties().get(KEY_TIMESTAMP);
    ByteBuffer encryptedKeyMetadata =
        EncryptionUtil.encryptManifestListKeyMetadata(
            keyEncryptionKey.unwrapped(), keyEncryptionKeyTimestamp, keyMetadata);
    EncryptedKey manifestListKey =
        new BaseEncryptedKey(
            generateKeyId(), encryptedKeyMetadata, keyEncryptionKey.key().keyId(), null);

    return new MintedKeys(
        manifestListKey, keyEncryptionKey.minted() ? keyEncryptionKey.key() : null);
  }

  /**
   * Finds an unexpired key encryption key in the metadata-sourced key set, or mints a fresh one.
   *
   * <p>Minting is pure: a freshly minted KEK is <em>not</em> stored in this manager. The returned
   * value carries the KEK, its unwrapped bytes (so the caller can encrypt without a cache round
   * trip), and a flag indicating whether it was newly minted (and therefore must be persisted).
   */
  private KeyEncryptionKey keyEncryptionKey() {
    // Find unexpired key encryption key
    for (EncryptedKey key : encryptionKeys.values()) {
      if (key.encryptedById().equals(tableKeyId)) { // this is a key encryption key
        String timestampProperty = key.properties().get(KEY_TIMESTAMP);
        long keyTimestamp = Long.parseLong(timestampProperty);
        if (currentTimeMillis() - keyTimestamp < KEY_ENCRYPTION_KEY_LIFESPAN_MS) {
          return new KeyEncryptionKey(key, unwrappedKeyCache().get(key.keyId()), false);
        }
      }
    }

    // No unexpired key encryption keys; mint one (without storing it)
    ByteBuffer unwrapped = newKey();
    ByteBuffer wrapped = kmsClient.wrapKey(unwrapped, tableKeyId);
    Map<String, String> properties = Maps.newHashMap();
    properties.put(KEY_TIMESTAMP, "" + currentTimeMillis());
    EncryptedKey key = new BaseEncryptedKey(generateKeyId(), wrapped, tableKeyId, properties);

    return new KeyEncryptionKey(key, unwrapped, true);
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

  /** The keys created by a single {@link #mintManifestListKey} call. */
  public static class MintedKeys {
    private final EncryptedKey manifestListKey;
    private final EncryptedKey keyEncryptionKey;

    private MintedKeys(EncryptedKey manifestListKey, EncryptedKey keyEncryptionKey) {
      this.manifestListKey = manifestListKey;
      this.keyEncryptionKey = keyEncryptionKey;
    }

    /** The newly minted manifest-list key. Never null. */
    public EncryptedKey manifestListKey() {
      return manifestListKey;
    }

    /**
     * The key encryption key that wraps the manifest-list key, if it was newly minted by this call
     * (and therefore not yet in table metadata), or {@code null} if an existing key was reused.
     */
    public EncryptedKey newKeyEncryptionKey() {
      return keyEncryptionKey;
    }
  }

  /**
   * A key encryption key together with its unwrapped bytes and whether it was minted by this call.
   */
  private static class KeyEncryptionKey {
    private final EncryptedKey key;
    private final ByteBuffer unwrapped;
    private final boolean minted;

    private KeyEncryptionKey(EncryptedKey key, ByteBuffer unwrapped, boolean minted) {
      this.key = key;
      this.unwrapped = unwrapped;
      this.minted = minted;
    }

    private EncryptedKey key() {
      return key;
    }

    private ByteBuffer unwrapped() {
      return unwrapped;
    }

    private boolean minted() {
      return minted;
    }
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
