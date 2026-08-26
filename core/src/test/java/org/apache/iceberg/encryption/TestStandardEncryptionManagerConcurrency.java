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
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.iceberg.ManifestListFile;
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.junit.jupiter.api.Test;

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
  void concurrentMintingPublishesEveryCompleteKeyPair() throws Exception {
    int numMints = 8;
    StandardEncryptionManager manager =
        EncryptionTestHelpers.createStandardEncryptionManager(new UnitestKMS());
    CountDownLatch buffersEntered = new CountDownLatch(numMints);
    CountDownLatch releaseBuffers = new CountDownLatch(1);
    ExecutorService executor = Executors.newFixedThreadPool(numMints);
    List<Future<String>> keyIds = Lists.newArrayList();

    try {
      for (int index = 0; index < numMints; index++) {
        keyIds.add(
            executor.submit(
                () ->
                    manager.addManifestListKeyMetadata(
                        new CoordinatedKeyMetadata(buffersEntered, releaseBuffers))));
      }

      assertThat(buffersEntered.await(WAIT_SECONDS, TimeUnit.SECONDS)).isTrue();
      assertThat(EncryptionUtil.encryptionKeys(manager)).isEmpty();
      releaseBuffers.countDown();

      List<String> manifestListKeyIds = Lists.newArrayList();
      for (Future<String> keyId : keyIds) {
        manifestListKeyIds.add(keyId.get(WAIT_SECONDS, TimeUnit.SECONDS));
      }

      Map<String, EncryptedKey> keys = EncryptionUtil.encryptionKeys(manager);
      for (String keyId : manifestListKeyIds) {
        assertCompletePair(keys, keyId);
      }

      assertThat(manifestListKeyIds).doesNotHaveDuplicates();
      assertThat(
              keys.values().stream()
                  .filter(key -> !UnitestKMS.MASTER_KEY_NAME1.equals(key.encryptedById())))
          .hasSize(numMints);
    } finally {
      releaseBuffers.countDown();
      executor.shutdownNow();
    }
  }

  @Test
  void javaSerializationUsesStableRegistrySnapshot() throws Exception {
    StandardEncryptionManager manager =
        EncryptionTestHelpers.createStandardEncryptionManager(new UnitestKMS());
    manager.addManifestListKeyMetadata(EncryptionTestHelpers.keyMetadata());
    Set<String> before = keyIds(manager);
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
                            coordinatedJavaRoundTrip(
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
    assertThat(keyIds(serialized.get())).isIn(before, after);
  }

  @Test
  void deserializesReleasedManagerState() throws Exception {
    StandardEncryptionManager manager =
        readJavaRoundTrip(Base64.getDecoder().decode(RELEASED_MANAGER_FIXTURE));
    Map<String, EncryptedKey> keys = EncryptionUtil.encryptionKeys(manager);
    EncryptedKey manifestListKey = keys.get(RELEASED_MANIFEST_LIST_KEY_ID);

    assertThat(manifestListKey).isNotNull();
    assertThat(keys)
        .hasSize(2)
        .containsKeys(RELEASED_MANIFEST_LIST_KEY_ID, manifestListKey.encryptedById());
    assertThat(
            EncryptionUtil.decryptManifestListKeyMetadata(
                manifestList(RELEASED_MANIFEST_LIST_KEY_ID), manager))
        .isEqualTo(ByteBuffer.wrap(Base64.getDecoder().decode(RELEASED_KEY_METADATA)));
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

    return readJavaRoundTrip(bytes.toByteArray());
  }

  private static StandardEncryptionManager readJavaRoundTrip(byte[] bytes) throws Exception {
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
      return (StandardEncryptionManager) in.readObject();
    }
  }

  private static Set<String> keyIds(StandardEncryptionManager manager) {
    return Set.copyOf(EncryptionUtil.encryptionKeys(manager).keySet());
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

  private static void assertCompletePair(Map<String, EncryptedKey> keys, String manifestListKeyId) {
    EncryptedKey manifestListKey = keys.get(manifestListKeyId);
    assertThat(manifestListKey).isNotNull();
    assertThat(keys).containsKey(manifestListKey.encryptedById());
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

  private static class CoordinatedKeyMetadata implements NativeEncryptionKeyMetadata {
    private final CountDownLatch buffersEntered;
    private final CountDownLatch releaseBuffers;
    private final NativeEncryptionKeyMetadata delegate = EncryptionTestHelpers.keyMetadata();

    private CoordinatedKeyMetadata(CountDownLatch buffersEntered, CountDownLatch releaseBuffers) {
      this.buffersEntered = buffersEntered;
      this.releaseBuffers = releaseBuffers;
    }

    @Override
    public ByteBuffer encryptionKey() {
      return delegate.encryptionKey();
    }

    @Override
    public ByteBuffer aadPrefix() {
      return delegate.aadPrefix();
    }

    @Override
    public ByteBuffer buffer() {
      buffersEntered.countDown();
      await(releaseBuffers);
      return delegate.buffer();
    }

    @Override
    public EncryptionKeyMetadata copy() {
      return this;
    }
  }
}
