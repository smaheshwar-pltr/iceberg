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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class TestStandardEncryptionManagerConcurrency {
  private static final long WAIT_SECONDS = 10;
  private static final long SERIAL_VERSION_UID = -5497522897222558303L;

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
  void serializationDoesNotExposeIncompleteKeyRegistry() throws Exception {
    BlockingKms kms = new BlockingKms();
    InvocationTrackingManager manager = newInvocationTrackingManager(kms);
    AtomicReference<StandardEncryptionManager> serialized = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread minter =
        new Thread(() -> capture(() -> manager.addManifestListKeyMetadata(keyMetadata()), failure));
    Thread serializer =
        new Thread(() -> capture(() -> serialized.set(roundTrip(manager)), failure));

    minter.start();
    try {
      kms.awaitWrap();
      serializer.start();
      manager.awaitSerializationInvocation();
    } finally {
      kms.releaseWrap();
      join(minter);
      join(serializer);
    }

    assertThat(failure.get()).isNull();
    assertCompleteKeyPairs(serialized.get().encryptionKeys());
  }

  @Test
  void snapshotDoesNotExposeIncompleteKeyRegistry() throws Exception {
    BlockingKms kms = new BlockingKms();
    InvocationTrackingManager manager = newInvocationTrackingManager(kms);
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
      manager.awaitSnapshotInvocation();
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
  void manifestListEncryptionKeysReturnsOnlyRequestedPair() {
    StandardEncryptionManager manager = newManager(new UnitestKMS());
    String firstKeyId = manager.addManifestListKeyMetadata(keyMetadata());
    String secondKeyId = manager.addManifestListKeyMetadata(keyMetadata());

    Map<String, EncryptedKey> keys =
        EncryptionUtil.manifestListEncryptionKeys(manager, secondKeyId);
    EncryptedKey manifestListKey = keys.get(secondKeyId);
    EncryptedKey keyEncryptionKey = keys.get(manifestListKey.encryptedById());
    byte metadataByte = manifestListKey.encryptedKeyMetadata().get(0);
    String keyTimestamp =
        keyEncryptionKey.properties().get(StandardEncryptionManager.KEY_TIMESTAMP);

    assertThat(keys)
        .hasSize(2)
        .containsKey(manifestListKey.encryptedById())
        .doesNotContainKey(firstKeyId);
    assertThatThrownBy(keys::clear)
        .isInstanceOf(UnsupportedOperationException.class)
        .hasMessage(null);

    manifestListKey.encryptedKeyMetadata().put(0, (byte) (metadataByte + 1));
    keyEncryptionKey.properties().put(StandardEncryptionManager.KEY_TIMESTAMP, "modified");

    Map<String, EncryptedKey> current =
        EncryptionUtil.manifestListEncryptionKeys(manager, secondKeyId);
    assertThat(current.get(secondKeyId).encryptedKeyMetadata().get(0)).isEqualTo(metadataByte);
    assertThat(
            current
                .get(manifestListKey.encryptedById())
                .properties()
                .get(StandardEncryptionManager.KEY_TIMESTAMP))
        .isEqualTo(keyTimestamp);
  }

  @Test
  void serialVersionUidRemainsCompatible() {
    assertThat(ObjectStreamClass.lookup(StandardEncryptionManager.class).getSerialVersionUID())
        .isEqualTo(SERIAL_VERSION_UID);
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

  private static void assertCompleteKeyPairs(Map<String, EncryptedKey> keys) {
    assertThat(keys).isNotEmpty();
    keys.values().stream()
        .filter(key -> !UnitestKMS.MASTER_KEY_NAME1.equals(key.encryptedById()))
        .forEach(key -> assertThat(keys).containsKey(key.encryptedById()));
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

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  private static class BlockingKms extends UnitestKMS {
    private final AtomicInteger wrapCalls = new AtomicInteger();
    private transient CountDownLatch wrapEntered = new CountDownLatch(1);
    private transient CountDownLatch allowWrap = new CountDownLatch(1);

    @Override
    public ByteBuffer wrapKey(ByteBuffer key, String wrappingKeyId) {
      wrapCalls.incrementAndGet();
      wrapEntered.countDown();
      try {
        if (!allowWrap.await(WAIT_SECONDS, TimeUnit.SECONDS)) {
          throw new AssertionError("Timed out waiting to release key wrapping");
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError("Interrupted while waiting to wrap key", e);
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
    private final transient CountDownLatch snapshotInvocation = new CountDownLatch(1);
    private final transient CountDownLatch serializationInvocation = new CountDownLatch(1);

    private InvocationTrackingManager(UnitestKMS kms) {
      super(List.of(), UnitestKMS.MASTER_KEY_NAME1, 16, kms);
    }

    @Override
    public String addManifestListKeyMetadata(NativeEncryptionKeyMetadata keyMetadata) {
      addInvocations.countDown();
      return super.addManifestListKeyMetadata(keyMetadata);
    }

    @Override
    Map<String, EncryptedKey> encryptionKeys() {
      if (snapshotInvocation != null) {
        snapshotInvocation.countDown();
      }

      return super.encryptionKeys();
    }

    private Object writeReplace() {
      serializationInvocation.countDown();
      return this;
    }

    private void awaitAddInvocations() throws InterruptedException {
      assertThat(addInvocations.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
    }

    private void awaitSnapshotInvocation() throws InterruptedException {
      assertThat(snapshotInvocation.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
    }

    private void awaitSerializationInvocation() throws InterruptedException {
      assertThat(serializationInvocation.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
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
