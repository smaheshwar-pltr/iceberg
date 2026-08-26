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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.spark.SparkConf;
import org.apache.spark.serializer.KryoSerializer;
import org.junit.jupiter.api.Test;

class TestStandardEncryptionManagerKryo {
  private static final long WAIT_SECONDS = 10;
  private static final String SENTINEL = "after-manager";

  @Test
  void serializationUsesStableRegistrySnapshot() throws Exception {
    StandardEncryptionManager manager =
        EncryptionTestHelpers.createStandardEncryptionManager(new UnitestKMS());
    manager.addManifestListKeyMetadata(EncryptionTestHelpers.keyMetadata());
    Set<String> before = keyIds(manager);
    CountDownLatch keySerializationStarted = new CountDownLatch(1);
    CountDownLatch continueSerialization = new CountDownLatch(1);
    AtomicReference<RoundTripResult> serialized = new AtomicReference<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Thread serializer =
        new Thread(
            () ->
                capture(
                    () ->
                        serialized.set(
                            coordinatedRoundTrip(
                                manager, keySerializationStarted, continueSerialization)),
                    failure));

    serializer.start();
    try {
      assertThat(keySerializationStarted.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
      manager.addManifestListKeyMetadata(EncryptionTestHelpers.keyMetadata());
    } finally {
      continueSerialization.countDown();
      join(serializer);
    }

    assertThat(failure.get()).isNull();
    Set<String> after = keyIds(manager);
    assertThat(keyIds(serialized.get().manager())).isIn(before, after);
    assertThat(serialized.get().sentinel()).isEqualTo(SENTINEL);
    assertCompletePairs(EncryptionUtil.encryptionKeys(serialized.get().manager()));
  }

  @SuppressWarnings("unchecked")
  private static RoundTripResult coordinatedRoundTrip(
      StandardEncryptionManager manager,
      CountDownLatch keySerializationStarted,
      CountDownLatch continueSerialization)
      throws Exception {
    Kryo kryo = new KryoSerializer(new SparkConf()).newKryo();
    Serializer<BaseEncryptedKey> delegate =
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

            delegate.write(current, output, key);
          }

          @Override
          public BaseEncryptedKey read(Kryo current, Input input, Class<BaseEncryptedKey> type) {
            return delegate.read(current, input, type);
          }
        });
    return roundTrip(kryo, manager);
  }

  private static RoundTripResult roundTrip(Kryo kryo, StandardEncryptionManager manager)
      throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (Output out = new Output(new ObjectOutputStream(bytes))) {
      kryo.writeClassAndObject(out, manager);
      kryo.writeObject(out, SENTINEL);
    }

    try (Input in =
        new Input(new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray())))) {
      return new RoundTripResult(
          (StandardEncryptionManager) kryo.readClassAndObject(in),
          kryo.readObject(in, String.class));
    }
  }

  private static Set<String> keyIds(StandardEncryptionManager manager) {
    return Set.copyOf(EncryptionUtil.encryptionKeys(manager).keySet());
  }

  private static void assertCompletePairs(Map<String, EncryptedKey> keys) {
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

  @FunctionalInterface
  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  private static class RoundTripResult {
    private final StandardEncryptionManager manager;
    private final String sentinel;

    private RoundTripResult(StandardEncryptionManager manager, String sentinel) {
      this.manager = manager;
      this.sentinel = sentinel;
    }

    private StandardEncryptionManager manager() {
      return manager;
    }

    private String sentinel() {
      return sentinel;
    }
  }
}
