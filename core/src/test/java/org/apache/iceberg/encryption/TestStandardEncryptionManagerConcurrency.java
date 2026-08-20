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

import static org.assertj.core.api.Assertions.assertThat;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.iceberg.ManifestListFile;
import org.apache.iceberg.TestHelpers;
import org.apache.iceberg.relocated.com.google.common.collect.Maps;
import org.junit.jupiter.api.Test;
import org.objenesis.strategy.StdInstantiatorStrategy;

class TestStandardEncryptionManagerConcurrency {
  private static final long WAIT_SECONDS = 10;
  private static final String RELEASED_MANIFEST_LIST_KEY_ID = "9P/B2bSlqbdOX3ggfw3MIw==";
  private static final String RELEASED_KEY_METADATA =
      "ASAAAQIDBAUGBwgJCgsMDQ4PAiAQERITFBUWFxgZGhscHR4fAA==";
  // Serialized by iceberg-core 1.11.0 after minting a manifest-list key with UnitestKMS.
  private static final String RELEASED_MANAGER_FIXTURE =
      String.join(
          "",
          "rO0ABXNyADdvcmcuYXBhY2hlLmljZWJlcmcuZW5jcnlwdGlvbi5TdGFuZGFyZEVuY3J5cHRpb25NYW5h",
          "Z2Vys7TgDVZ5HaECAAVJAA1kYXRhS2V5TGVuZ3RoSgANdGVzdFRpbWVTaGlmdEwADmVuY3J5cHRpb25L",
          "ZXlzdAAPTGphdmEvdXRpbC9NYXA7TAAJa21zQ2xpZW50dAAzTG9yZy9hcGFjaGUvaWNlYmVyZy9lbmNy",
          "eXB0aW9uL0tleU1hbmFnZW1lbnRDbGllbnQ7TAAKdGFibGVLZXlJZHQAEkxqYXZhL2xhbmcvU3RyaW5n",
          "O3hwAAAAEAAAAAAAAAAAc3IAJ29yZy5hcGFjaGUuaWNlYmVyZy51dGlsLlNlcmlhbGl6YWJsZU1hcNEh",
          "o5wvJt5YAgABTAAJY29waWVkTWFwcQB+AAF4cHNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwAC",
          "RgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAACdAAYZ2ptRTd2aUpGT3FY",
          "dko4UVd4QlYzdz09c3IALm9yZy5hcGFjaGUuaWNlYmVyZy5lbmNyeXB0aW9uLkJhc2VFbmNyeXB0ZWRL",
          "ZXnhdynLStYT3AIABEwADWVuY3J5cHRlZEJ5SWRxAH4AA0wABWtleUlkcQB+AANbAAtrZXlNZXRhZGF0",
          "YXQAAltCTAAKcHJvcGVydGllc3EAfgABeHB0AARrZXlBcQB+AAl1cgACW0Ks8xf4BghU4AIAAHhwAAAA",
          "LA0xu+rZnxGKeEZBosgUA4XSKs9s050LtNbnD9UZLWxs6hvLRe2DIeSHPSOpc3EAfgAFc3EAfgAHP0AA",
          "AAAAAAF3CAAAAAIAAAABdAANS0VZX1RJTUVTVEFNUHQADTE3ODcxNzkwNDg4NDN4dAAYOVAvQjJiU2xx",
          "YmRPWDNnZ2Z3M01Jdz09c3EAfgAKcQB+AAlxAH4AFHVxAH4ADgAAAEGSrKRujkigYQOrYFTK2gEo1t5w",
          "L/1Hqc45h4OI+CEhYM4MIh/+a8CjoUyVCIW2d8WIoyR5tLmCXinaTxWwQQJ9uHB4c3IAKG9yZy5hcGFj",
          "aGUuaWNlYmVyZy5lbmNyeXB0aW9uLlVuaXRlc3RLTVNhs1Igyo6qHAIAAHhyACtvcmcuYXBhY2hlLmlj",
          "ZWJlcmcuZW5jcnlwdGlvbi5NZW1vcnlNb2NrS01Tor3jwgNw00ACAAFMAAptYXN0ZXJLZXlzcQB+AAF4",
          "cHNxAH4ABz9AAAAAAAADdwgAAAAEAAAAAnEAfgANdXEAfgAOAAAAEDAxMjM0NTY3ODkwMTIzNDV0AARr",
          "ZXlCdXEAfgAOAAAAEDExMjM0NTY3ODkwMTIzNDV4cQB+AA0=");

  @Test
  void concurrentMintingCreatesOneKeyEncryptionKey() throws Exception {
    BlockingKms kms = new BlockingKms();
    InvocationTrackingManager manager = newInvocationTrackingManager(kms);
    AtomicReference<String> firstKey = new AtomicReference<>();
    AtomicReference<String> secondKey = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread first =
        new Thread(
            () ->
                capture(
                    () -> firstKey.set(manager.addManifestListKeyMetadata(keyMetadata())),
                    failure));
    Thread second =
        new Thread(
            () ->
                capture(
                    () -> secondKey.set(manager.addManifestListKeyMetadata(keyMetadata())),
                    failure));

    first.start();
    try {
      kms.awaitWrap();
      second.start();
      manager.awaitAddInvocations();
    } finally {
      kms.releaseWrap();
      join(first);
      join(second);
    }

    assertThat(failure.get()).isNull();
    assertThat(kms.wrapCalls()).isEqualTo(1);
    assertThat(manager.encryptionKeys()).containsKeys(firstKey.get(), secondKey.get()).hasSize(3);
    assertThat(
            manager.encryptionKeys().values().stream()
                .filter(key -> UnitestKMS.MASTER_KEY_NAME1.equals(key.encryptedById())))
        .hasSize(1);
  }

  @Test
  void blockedKeyCreationDoesNotBlockExistingKeyReads() throws Exception {
    BlockingKms kms = new BlockingKms(2);
    StandardEncryptionManager initialManager = newManager(kms);
    String existingManifestListKey = initialManager.addManifestListKeyMetadata(keyMetadata());
    StandardEncryptionManager manager =
        new StandardEncryptionManager(
            List.copyOf(initialManager.encryptionKeys().values()),
            UnitestKMS.MASTER_KEY_NAME1,
            16,
            kms);
    manager.setTestTimeShift(TimeUnit.DAYS.toMillis(731));
    AtomicReference<ByteBuffer> loadedKey = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread minter =
        new Thread(() -> capture(() -> manager.addManifestListKeyMetadata(keyMetadata()), failure));
    Thread reader =
        new Thread(
            () ->
                capture(
                    () -> loadedKey.set(manager.encryptedByKey(existingManifestListKey)), failure));

    minter.start();
    try {
      kms.awaitWrap();
      reader.start();
      join(reader);
    } finally {
      kms.releaseWrap();
      join(minter);
      join(reader);
    }

    assertThat(failure.get()).isNull();
    assertThat(loadedKey.get()).isNotNull();
  }

  @Test
  void javaSerializationDoesNotWaitForKeyCreation() throws Exception {
    assertSerializationDoesNotWait(TestStandardEncryptionManagerConcurrency::roundTrip);
  }

  @Test
  void kryoSerializationDoesNotWaitForKeyCreation() throws Exception {
    assertSerializationDoesNotWait(TestHelpers.KryoHelpers::roundTripSerialize);
  }

  @Test
  void javaSerializationUsesStableRegistrySnapshot() throws Exception {
    assertSerializationUsesStableRegistrySnapshot(
        TestStandardEncryptionManagerConcurrency::coordinatedJavaRoundTrip);
  }

  @Test
  void kryoSerializationUsesStableRegistrySnapshot() throws Exception {
    assertSerializationUsesStableRegistrySnapshot(
        TestStandardEncryptionManagerConcurrency::coordinatedKryoRoundTrip);
  }

  @Test
  void snapshotDoesNotExposeIncompleteKeyRegistry() throws Exception {
    BlockingKms kms = new BlockingKms(2);
    InvocationTrackingManager manager = newInvocationTrackingManager(kms);
    manager.addManifestListKeyMetadata(keyMetadata());
    manager.setTestTimeShift(TimeUnit.DAYS.toMillis(731));
    AtomicReference<Map<String, EncryptedKey>> snapshot = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread minter =
        new Thread(() -> capture(() -> manager.addManifestListKeyMetadata(keyMetadata()), failure));
    Thread reader =
        new Thread(() -> capture(() -> snapshot.set(manager.encryptionKeys()), failure));

    minter.start();
    try {
      kms.awaitWrap();
      reader.start();
      join(reader);
    } finally {
      kms.releaseWrap();
      join(minter);
      join(reader);
    }

    assertThat(failure.get()).isNull();
    assertCompleteKeyPairs(snapshot.get());
  }

  @Test
  void encryptionKeysReturnsMutableDetachedSnapshot() {
    StandardEncryptionManager manager = newManager(new UnitestKMS());
    String keyId = manager.addManifestListKeyMetadata(keyMetadata());
    Map<String, EncryptedKey> snapshot = manager.encryptionKeys();
    EncryptedKey manifestListKey = snapshot.get(keyId);
    EncryptedKey keyEncryptionKey = snapshot.get(manifestListKey.encryptedById());
    byte metadataByte = manifestListKey.encryptedKeyMetadata().get(0);
    String keyTimestamp =
        keyEncryptionKey.properties().get(StandardEncryptionManager.KEY_TIMESTAMP);

    manifestListKey.encryptedKeyMetadata().put(0, (byte) (metadataByte + 1));
    keyEncryptionKey.properties().put(StandardEncryptionManager.KEY_TIMESTAMP, "modified");
    snapshot.clear();

    Map<String, EncryptedKey> current = manager.encryptionKeys();
    assertThat(snapshot).isEmpty();
    assertThat(current.get(keyId).encryptedKeyMetadata().get(0)).isEqualTo(metadataByte);
    assertThat(
            current
                .get(manifestListKey.encryptedById())
                .properties()
                .get(StandardEncryptionManager.KEY_TIMESTAMP))
        .isEqualTo(keyTimestamp);
  }

  @Test
  void constructorDetachesCallerOwnedKeyState() {
    BaseEncryptedKey input =
        new BaseEncryptedKey(
            "key-id",
            ByteBuffer.wrap(new byte[] {1, 2, 3}),
            UnitestKMS.MASTER_KEY_NAME1,
            Map.of(StandardEncryptionManager.KEY_TIMESTAMP, "timestamp"));
    StandardEncryptionManager manager =
        new StandardEncryptionManager(
            List.of(input), UnitestKMS.MASTER_KEY_NAME1, 16, initializedKms());

    input.encryptedKeyMetadata().put(0, (byte) 9);
    input.properties().put(StandardEncryptionManager.KEY_TIMESTAMP, "modified");

    EncryptedKey retained = manager.encryptionKey(input.keyId());
    assertThat(retained.encryptedKeyMetadata()).isEqualTo(ByteBuffer.wrap(new byte[] {1, 2, 3}));
    assertThat(retained.properties())
        .containsEntry(StandardEncryptionManager.KEY_TIMESTAMP, "timestamp");
  }

  @Test
  void kmsBuffersCannotMutateManagerState() {
    MutableBufferKms mintingKms = new MutableBufferKms();
    StandardEncryptionManager manager = newManager(mintingKms);
    String manifestListKeyId = manager.addManifestListKeyMetadata(keyMetadata());
    EncryptedKey manifestListKey = manager.encryptionKey(manifestListKeyId);
    String keyEncryptionKeyId = manifestListKey.encryptedById();
    ByteBuffer unwrappedKey = manager.encryptedByKey(manifestListKeyId);
    ByteBuffer wrappedKey = manager.encryptionKey(keyEncryptionKeyId).encryptedKeyMetadata();

    mintingKms.mutateWrapBuffers();

    assertThat(manager.encryptedByKey(manifestListKeyId)).isEqualTo(unwrappedKey);
    assertThat(manager.encryptionKey(keyEncryptionKeyId).encryptedKeyMetadata())
        .isEqualTo(wrappedKey);

    MutableBufferKms loadingKms = new MutableBufferKms();
    StandardEncryptionManager reloaded =
        new StandardEncryptionManager(
            List.copyOf(manager.encryptionKeys().values()),
            UnitestKMS.MASTER_KEY_NAME1,
            16,
            initializedKms(loadingKms));
    ByteBuffer loadedKey = reloaded.encryptedByKey(manifestListKeyId);

    loadingKms.mutateUnwrapBuffer();

    assertThat(reloaded.encryptedByKey(manifestListKeyId)).isEqualTo(loadedKey);
  }

  @Test
  void deserializesReleasedManagerState() throws Exception {
    StandardEncryptionManager manager =
        deserialize(Base64.getDecoder().decode(RELEASED_MANAGER_FIXTURE));
    EncryptedKey manifestListKey = manager.encryptionKey(RELEASED_MANIFEST_LIST_KEY_ID);

    assertThat(manifestListKey).isNotNull();
    assertThat(manager.encryptionKeys())
        .hasSize(2)
        .containsKeys(RELEASED_MANIFEST_LIST_KEY_ID, manifestListKey.encryptedById());
    assertThat(
            EncryptionUtil.decryptManifestListKeyMetadata(
                manifestList(RELEASED_MANIFEST_LIST_KEY_ID), manager))
        .isEqualTo(ByteBuffer.wrap(Base64.getDecoder().decode(RELEASED_KEY_METADATA)));
  }

  private static StandardEncryptionManager newManager(UnitestKMS kms) {
    return new StandardEncryptionManager(
        List.of(), UnitestKMS.MASTER_KEY_NAME1, 16, initializedKms(kms));
  }

  private static InvocationTrackingManager newInvocationTrackingManager(UnitestKMS kms) {
    return new InvocationTrackingManager(initializedKms(kms));
  }

  private static UnitestKMS initializedKms() {
    return initializedKms(new UnitestKMS());
  }

  private static <T extends UnitestKMS> T initializedKms(T kms) {
    kms.initialize(Map.of());
    return kms;
  }

  private static NativeEncryptionKeyMetadata keyMetadata() {
    return new StandardKeyMetadata(new byte[16], new byte[16]);
  }

  private static ManifestListFile manifestList(String keyId) {
    return new ManifestListFile() {
      @Override
      public String location() {
        return "test-manifest-list";
      }

      @Override
      public String encryptionKeyID() {
        return keyId;
      }

      @Override
      public ByteBuffer decryptKeyMetadata(EncryptionManager em) {
        return EncryptionUtil.decryptManifestListKeyMetadata(this, em);
      }
    };
  }

  private static void assertCompleteKeyPairs(Map<String, EncryptedKey> keys) {
    assertThat(keys).isNotEmpty();
    keys.values().stream()
        .filter(key -> !UnitestKMS.MASTER_KEY_NAME1.equals(key.encryptedById()))
        .forEach(key -> assertThat(keys).containsKey(key.encryptedById()));
  }

  private static void assertSerializationDoesNotWait(ManagerRoundTrip roundTrip) throws Exception {
    BlockingKms kms = new BlockingKms(2);
    StandardEncryptionManager manager = newManager(kms);
    manager.addManifestListKeyMetadata(keyMetadata());
    manager.setTestTimeShift(TimeUnit.DAYS.toMillis(731));
    AtomicReference<StandardEncryptionManager> serialized = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread minter =
        new Thread(() -> capture(() -> manager.addManifestListKeyMetadata(keyMetadata()), failure));
    Thread serializer =
        new Thread(() -> capture(() -> serialized.set(roundTrip.apply(manager)), failure));

    minter.start();
    try {
      kms.awaitWrap();
      serializer.start();
      join(serializer);
    } finally {
      kms.releaseWrap();
      join(minter);
      join(serializer);
    }

    assertThat(failure.get()).isNull();
    assertCompleteKeyPairs(serialized.get().encryptionKeys());
    serialized.get().addManifestListKeyMetadata(keyMetadata());
    assertCompleteKeyPairs(serialized.get().encryptionKeys());
  }

  private static void assertSerializationUsesStableRegistrySnapshot(
      CoordinatedManagerRoundTrip roundTrip) throws Exception {
    StandardEncryptionManager manager = newManager(new BlockingKms(Integer.MAX_VALUE));
    manager.addManifestListKeyMetadata(keyMetadata());
    CountDownLatch keySerializationStarted = new CountDownLatch(1);
    CountDownLatch continueSerialization = new CountDownLatch(1);
    AtomicReference<StandardEncryptionManager> serialized = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread serializer =
        new Thread(
            () ->
                capture(
                    () ->
                        serialized.set(
                            roundTrip.apply(
                                manager, keySerializationStarted, continueSerialization)),
                    failure));

    serializer.start();
    try {
      await(keySerializationStarted);
      manager.addManifestListKeyMetadata(keyMetadata());
    } finally {
      continueSerialization.countDown();
      join(serializer);
    }

    assertThat(failure.get()).isNull();
    assertCompleteKeyPairs(serialized.get().encryptionKeys());
  }

  private static StandardEncryptionManager coordinatedJavaRoundTrip(
      StandardEncryptionManager manager,
      CountDownLatch keySerializationStarted,
      CountDownLatch continueSerialization)
      throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream out =
        new ObjectOutputStream(bytes) {
          {
            enableReplaceObject(true);
          }

          @Override
          protected Object replaceObject(Object object) throws IOException {
            if (object instanceof EncryptedKey && keySerializationStarted.getCount() > 0) {
              keySerializationStarted.countDown();
              await(continueSerialization);
            }

            return object;
          }
        }) {
      out.writeObject(manager);
    }

    return deserialize(bytes.toByteArray());
  }

  @SuppressWarnings("unchecked")
  private static StandardEncryptionManager coordinatedKryoRoundTrip(
      StandardEncryptionManager manager,
      CountDownLatch keySerializationStarted,
      CountDownLatch continueSerialization)
      throws Exception {
    Kryo kryo = new Kryo();
    kryo.setInstantiatorStrategy(
        new Kryo.DefaultInstantiatorStrategy(new StdInstantiatorStrategy()));
    Serializer<BaseEncryptedKey> keySerializer =
        (Serializer<BaseEncryptedKey>) kryo.getDefaultSerializer(BaseEncryptedKey.class);
    kryo.register(
        BaseEncryptedKey.class,
        new Serializer<BaseEncryptedKey>() {
          @Override
          public void write(Kryo current, Output output, BaseEncryptedKey key) {
            if (keySerializationStarted.getCount() > 0) {
              keySerializationStarted.countDown();
              await(continueSerialization);
            }

            keySerializer.write(current, output, key);
          }

          @Override
          public BaseEncryptedKey read(Kryo current, Input input, Class<BaseEncryptedKey> type) {
            return keySerializer.read(current, input, type);
          }
        });

    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (Output out = new Output(new ObjectOutputStream(bytes))) {
      kryo.writeClassAndObject(out, manager);
    }

    try (Input in =
        new Input(new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray())))) {
      return (StandardEncryptionManager) kryo.readClassAndObject(in);
    }
  }

  private static void capture(ThrowingRunnable action, AtomicReference<Throwable> failure) {
    try {
      action.run();
    } catch (Throwable t) {
      failure.compareAndSet(null, t);
    }
  }

  private static void join(Thread thread) throws InterruptedException {
    thread.join(TimeUnit.SECONDS.toMillis(WAIT_SECONDS));
    assertThat(thread.isAlive()).isFalse();
  }

  private static void await(CountDownLatch latch) {
    try {
      if (!latch.await(WAIT_SECONDS, TimeUnit.SECONDS)) {
        throw new AssertionError("Timed out waiting for coordinated serialization");
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError("Interrupted during coordinated serialization", e);
    }
  }

  @SuppressWarnings("unchecked")
  private static <T> T roundTrip(T value) throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(value);
    }

    try (ObjectInputStream in =
        new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      return (T) in.readObject();
    }
  }

  private static StandardEncryptionManager deserialize(byte[] bytes) throws Exception {
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
      return (StandardEncryptionManager) in.readObject();
    }
  }

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  @FunctionalInterface
  private interface ManagerRoundTrip {
    StandardEncryptionManager apply(StandardEncryptionManager manager) throws Exception;
  }

  @FunctionalInterface
  private interface CoordinatedManagerRoundTrip {
    StandardEncryptionManager apply(
        StandardEncryptionManager manager,
        CountDownLatch keySerializationStarted,
        CountDownLatch continueSerialization)
        throws Exception;
  }

  private static class BlockingKms extends UnitestKMS {
    private final AtomicInteger wrapCalls = new AtomicInteger();
    private final int blockedWrapCall;
    private transient CountDownLatch wrapEntered = new CountDownLatch(1);
    private transient CountDownLatch allowWrap = new CountDownLatch(1);

    private BlockingKms() {
      this(1);
    }

    private BlockingKms(int blockedWrapCall) {
      this.blockedWrapCall = blockedWrapCall;
    }

    @Override
    public void initialize(Map<String, String> properties) {
      super.initialize(properties);
      // Keep the Kryo round trip focused on the manager rather than UnitestKMS's ImmutableMap.
      this.masterKeys = Maps.newHashMap(this.masterKeys);
    }

    @Override
    public ByteBuffer wrapKey(ByteBuffer key, String wrappingKeyId) {
      int call = wrapCalls.incrementAndGet();
      if (call == blockedWrapCall) {
        wrapEntered.countDown();
        try {
          if (!allowWrap.await(WAIT_SECONDS, TimeUnit.SECONDS)) {
            throw new AssertionError("Timed out waiting to release key wrapping");
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new AssertionError("Interrupted while waiting to wrap key", e);
        }
      }

      return super.wrapKey(key, wrappingKeyId);
    }

    private void awaitWrap() throws InterruptedException {
      assertThat(wrapEntered.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
    }

    private void releaseWrap() {
      allowWrap.countDown();
    }

    private int wrapCalls() {
      return wrapCalls.get();
    }
  }

  private static class InvocationTrackingManager extends StandardEncryptionManager {
    private final transient CountDownLatch addInvocations = new CountDownLatch(2);

    private InvocationTrackingManager(UnitestKMS kms) {
      super(List.of(), UnitestKMS.MASTER_KEY_NAME1, 16, kms);
    }

    @Override
    public String addManifestListKeyMetadata(NativeEncryptionKeyMetadata keyMetadata) {
      addInvocations.countDown();
      return super.addManifestListKeyMetadata(keyMetadata);
    }

    private void awaitAddInvocations() throws InterruptedException {
      assertThat(addInvocations.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
    }
  }

  private static class MutableBufferKms extends UnitestKMS {
    private ByteBuffer wrapInput;
    private ByteBuffer wrapOutput;
    private ByteBuffer unwrapOutput;

    @Override
    public ByteBuffer wrapKey(ByteBuffer key, String wrappingKeyId) {
      this.wrapInput = key;
      this.wrapOutput = super.wrapKey(key, wrappingKeyId);
      return wrapOutput;
    }

    @Override
    public ByteBuffer unwrapKey(ByteBuffer wrappedKey, String wrappingKeyId) {
      this.unwrapOutput = super.unwrapKey(wrappedKey, wrappingKeyId);
      return unwrapOutput;
    }

    private void mutateWrapBuffers() {
      mutate(wrapInput);
      mutate(wrapOutput);
    }

    private void mutateUnwrapBuffer() {
      mutate(unwrapOutput);
    }

    private static void mutate(ByteBuffer buffer) {
      buffer.put(0, (byte) (buffer.get(0) + 1));
    }
  }
}
