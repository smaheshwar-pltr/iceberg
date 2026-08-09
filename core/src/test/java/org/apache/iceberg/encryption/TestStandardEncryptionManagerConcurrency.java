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

  @Test
  void concurrentMintingCreatesOneKeyEncryptionKey() throws Exception {
    BlockingKms kms = new BlockingKms();
    StandardEncryptionManager manager = newManager(kms);
    AtomicReference<String> firstKey = new AtomicReference<>();
    AtomicReference<String> secondKey = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    CountDownLatch secondStarted = new CountDownLatch(1);
    Thread first =
        new Thread(
            () ->
                capture(
                    () -> firstKey.set(manager.addManifestListKeyMetadata(keyMetadata())),
                    failure));
    Thread second =
        new Thread(
            () -> {
              secondStarted.countDown();
              capture(
                  () -> secondKey.set(manager.addManifestListKeyMetadata(keyMetadata())), failure);
            });

    first.start();
    kms.awaitWrap();
    second.start();
    assertThat(secondStarted.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();

    try {
      awaitBlocked(second);
      assertThat(kms.wrapCalls()).isEqualTo(1);
    } finally {
      kms.releaseWrap();
      join(first);
      join(second);
    }

    assertThat(failure.get()).isNull();
    assertThat(manager.encryptionKeys()).containsKeys(firstKey.get(), secondKey.get()).hasSize(3);
    assertThat(
            manager.encryptionKeys().values().stream()
                .filter(key -> UnitestKMS.MASTER_KEY_NAME1.equals(key.encryptedById()))
                .count())
        .isEqualTo(1L);
  }

  @Test
  void serializationWaitsForCompleteKeyMint() throws Exception {
    BlockingKms kms = new BlockingKms();
    StandardEncryptionManager manager = newManager(kms);
    AtomicReference<String> keyId = new AtomicReference<>();
    AtomicReference<StandardEncryptionManager> serialized = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    CountDownLatch serializationStarted = new CountDownLatch(1);
    Thread minter =
        new Thread(
            () ->
                capture(
                    () -> keyId.set(manager.addManifestListKeyMetadata(keyMetadata())), failure));
    Thread serializer =
        new Thread(
            () -> {
              serializationStarted.countDown();
              capture(() -> serialized.set(roundTrip(manager)), failure);
            });

    minter.start();
    kms.awaitWrap();
    serializer.start();
    assertThat(serializationStarted.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();

    try {
      awaitBlocked(serializer);
      assertThat(serialized.get()).isNull();
    } finally {
      kms.releaseWrap();
      join(minter);
      join(serializer);
    }

    assertThat(failure.get()).isNull();
    EncryptedKey manifestListKey = serialized.get().encryptionKeys().get(keyId.get());
    assertThat(manifestListKey).isNotNull();
    assertThat(serialized.get().encryptionKeys())
        .containsKey(manifestListKey.encryptedById())
        .hasSize(2);
    assertThat(serialized.get().encryptedByKey(keyId.get())).isNotNull();
  }

  @Test
  void encryptionKeysReturnsImmutableSnapshot() {
    StandardEncryptionManager manager = newManager(new UnitestKMS());
    String firstKey = manager.addManifestListKeyMetadata(keyMetadata());
    Map<String, EncryptedKey> snapshot = manager.encryptionKeys();

    String secondKey = manager.addManifestListKeyMetadata(keyMetadata());

    assertThat(snapshot).containsKey(firstKey).doesNotContainKey(secondKey).hasSize(2);
    assertThatThrownBy(snapshot::clear)
        .isInstanceOf(UnsupportedOperationException.class)
        .hasMessage(null);
  }

  private static StandardEncryptionManager newManager(UnitestKMS kms) {
    kms.initialize(Map.of());
    return new StandardEncryptionManager(List.of(), UnitestKMS.MASTER_KEY_NAME1, 16, kms);
  }

  private static NativeEncryptionKeyMetadata keyMetadata() {
    return new StandardKeyMetadata(new byte[16], new byte[16]);
  }

  private static void capture(ThrowingRunnable action, AtomicReference<Throwable> failure) {
    try {
      action.run();
    } catch (Throwable t) {
      failure.compareAndSet(null, t);
    }
  }

  private static void awaitBlocked(Thread thread) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(WAIT_SECONDS);
    while (thread.isAlive()
        && thread.getState() != Thread.State.BLOCKED
        && System.nanoTime() < deadline) {
      Thread.yield();
    }

    assertThat(thread.getState()).isEqualTo(Thread.State.BLOCKED);
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
}
