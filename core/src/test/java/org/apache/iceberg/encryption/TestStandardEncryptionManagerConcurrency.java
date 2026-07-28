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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.junit.jupiter.api.Test;

public class TestStandardEncryptionManagerConcurrency {

  private static final int THREADS = 4;
  private static final int KEYS_PER_THREAD = 50;
  private static final int ROUNDS = 300;

  @Test
  public void testConcurrentMintingIsThreadSafe() throws Exception {
    StandardEncryptionManager manager = newManager();

    List<String> keyIds = Lists.newArrayList();
    for (List<String> perThread :
        runConcurrently(
            () -> {
              List<String> ids = Lists.newArrayList();
              for (int i = 0; i < KEYS_PER_THREAD; i++) {
                ids.add(manager.addManifestListKeyMetadata(keyMetadata()));
                manager.encryptionKeys().forEach((id, key) -> {}); // concurrent read must not throw
              }
              return ids;
            })) {
      keyIds.addAll(perThread);
    }

    // No lost updates or duplicate ids under concurrency, and every minted key resolves.
    assertThat(Set.copyOf(keyIds)).hasSize(THREADS * KEYS_PER_THREAD);
    for (String keyId : keyIds) {
      assertThat(manager.encryptedByKey(keyId)).isNotNull();
    }

    // keyEncryptionKeyID()'s check-then-mint is atomic: exactly one key encryption key is created.
    long kekCount =
        manager.encryptionKeys().values().stream()
            .filter(key -> key.encryptedById().equals(UnitestKMS.MASTER_KEY_NAME1))
            .count();
    assertThat(kekCount).isEqualTo(1L);
  }

  @Test
  public void testConcurrentSerializationWhileMintingStaysConsistent() throws Exception {
    StandardEncryptionManager manager = newManager();
    List<String> seeded = Lists.newArrayList();
    for (int i = 0; i < 10; i++) {
      seeded.add(manager.addManifestListKeyMetadata(keyMetadata()));
    }

    AtomicReference<Throwable> failure = new AtomicReference<>();
    CountDownLatch start = new CountDownLatch(1);
    Thread minter =
        new Thread(
            () -> {
              try {
                start.await();
                for (int i = 0; i < ROUNDS; i++) {
                  manager.addManifestListKeyMetadata(keyMetadata());
                }
              } catch (Throwable t) {
                failure.compareAndSet(null, t);
              }
            });

    minter.start();
    start.countDown();
    // writeObject is synchronized, so serialization never traverses the key map mid-put: every
    // round trip is a complete, still-functional snapshot rather than a corrupt stream.
    for (int i = 0; i < ROUNDS; i++) {
      assertThat(roundTrip(manager).encryptionKeys().keySet()).containsAll(seeded);
    }
    minter.join(TimeUnit.SECONDS.toMillis(30));

    assertThat(failure.get()).isNull();
  }

  private static StandardEncryptionManager newManager() {
    return (StandardEncryptionManager) EncryptionTestHelpers.createEncryptionManager();
  }

  private static NativeEncryptionKeyMetadata keyMetadata() {
    return new StandardKeyMetadata(new byte[16], new byte[16]);
  }

  private static List<List<String>> runConcurrently(Callable<List<String>> task) throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(THREADS);
    try {
      CyclicBarrier barrier = new CyclicBarrier(THREADS);
      List<Future<List<String>>> futures = Lists.newArrayList();
      for (int t = 0; t < THREADS; t++) {
        futures.add(
            pool.submit(
                () -> {
                  barrier.await();
                  return task.call();
                }));
      }

      List<List<String>> results = Lists.newArrayList();
      for (Future<List<String>> future : futures) {
        try {
          results.add(future.get(60, TimeUnit.SECONDS));
        } catch (ExecutionException e) {
          throw new AssertionError("Concurrent task failed", e.getCause());
        }
      }
      return results;
    } finally {
      pool.shutdownNow();
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
}
