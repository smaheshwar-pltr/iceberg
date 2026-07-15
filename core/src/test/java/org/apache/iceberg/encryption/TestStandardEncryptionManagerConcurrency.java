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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

public class TestStandardEncryptionManagerConcurrency {

  private static final int THREAD_COUNT = 8;
  private static final int KEYS_PER_THREAD = 200;

  @Test
  public void testConcurrentKeyAdditionsKeepAllKeys() throws InterruptedException {
    StandardEncryptionManager manager =
        (StandardEncryptionManager) EncryptionTestHelpers.createEncryptionManager();

    List<String> addedKeyIds = new CopyOnWriteArrayList<>();
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
                  addedKeyIds.add(manager.addManifestListKeyMetadata(keyMetadata()));
                  // Reading keys concurrently with additions must not throw or lose entries.
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
    assertThat(addedKeyIds).hasSize(THREAD_COUNT * KEYS_PER_THREAD);
    assertThat(manager.encryptionKeys().keySet()).containsAll(addedKeyIds);
  }

  private static NativeEncryptionKeyMetadata keyMetadata() {
    return new StandardKeyMetadata(new byte[16], new byte[16]);
  }
}
