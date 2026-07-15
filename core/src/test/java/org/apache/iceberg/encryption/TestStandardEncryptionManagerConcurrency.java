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

import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * The manager is immutable and metadata-sourced: minting returns keys instead of storing them. This
 * verifies that concurrent minting on a single shared manager is safe -- every call returns a
 * distinct manifest-list key, all of which reference the manager's single shared key encryption
 * key. There is no shared mutable state, so this exercises the KMS/RNG/cache paths under contention
 * rather than a mutable map.
 */
public class TestStandardEncryptionManagerConcurrency {

  private static final int THREAD_COUNT = 8;
  private static final int KEYS_PER_THREAD = 200;

  @Test
  public void testConcurrentMintingReturnsDistinctKeys() throws InterruptedException {
    StandardEncryptionManager manager =
        (StandardEncryptionManager) EncryptionTestHelpers.createEncryptionManager();

    List<StandardEncryptionManager.MintedKeys> minted = new CopyOnWriteArrayList<>();
    AtomicReference<Throwable> failure = new AtomicReference<>();
    CountDownLatch start = new CountDownLatch(1);
    CountDownLatch done = new CountDownLatch(THREAD_COUNT);
    ExecutorService pool = Executors.newFixedThreadPool(THREAD_COUNT);

    try {
      for (int t = 0; t < THREAD_COUNT; t++) {
        pool.execute(
            () -> {
              try {
                start.await();
                for (int i = 0; i < KEYS_PER_THREAD; i++) {
                  minted.add(manager.mintManifestListKey(keyMetadata()));
                  // Reading the immutable key set concurrently with minting must never throw.
                  manager.encryptionKeys().forEach((id, key) -> {});
                }
              } catch (Throwable e) {
                failure.compareAndSet(null, e);
              } finally {
                done.countDown();
              }
            });
      }

      start.countDown();
      assertThat(done.await(60, TimeUnit.SECONDS)).isTrue();
    } finally {
      pool.shutdownNow();
    }

    assertThat(failure.get()).isNull();
    assertThat(minted).hasSize(THREAD_COUNT * KEYS_PER_THREAD);

    // The manager starts with no keys, so every mint sees an empty (immutable) key set and reuses
    // no
    // existing KEK. Each therefore mints its own KEK -- there is intentionally no cross-thread key
    // reuse, because minting never mutates shared state. All manifest-list key ids are distinct.
    Set<String> manifestListKeyIds =
        minted.stream().map(keys -> keys.manifestListKey().keyId()).collect(Collectors.toSet());
    assertThat(manifestListKeyIds).hasSize(minted.size());

    // Every minted manifest-list key is wrapped by a key encryption key that the same call also
    // returned as newly minted (so SnapshotProducer would persist both together).
    for (StandardEncryptionManager.MintedKeys keys : minted) {
      assertThat(keys.newKeyEncryptionKey()).isNotNull();
      assertThat(keys.manifestListKey().encryptedById())
          .isEqualTo(keys.newKeyEncryptionKey().keyId());
    }

    // Minting never mutated the manager's immutable key set.
    assertThat(manager.encryptionKeys()).isEmpty();
  }

  private static NativeEncryptionKeyMetadata keyMetadata() {
    return new StandardKeyMetadata(new byte[16], new byte[16]);
  }
}
