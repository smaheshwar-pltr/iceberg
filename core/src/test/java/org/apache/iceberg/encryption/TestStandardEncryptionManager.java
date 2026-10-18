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

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.apache.iceberg.TestHelpers;
import org.apache.iceberg.encryption.StandardEncryptionManager.FileEncryptionKeys;
import org.apache.iceberg.inmemory.InMemoryFileIO;
import org.apache.iceberg.io.FileIO;
import org.apache.iceberg.relocated.com.google.common.collect.Maps;
import org.apache.iceberg.util.Tasks;
import org.junit.jupiter.api.Test;

class TestStandardEncryptionManager {
  private static final int THREADS = 8;
  private static final int KEYS = 2000;
  private static final FileIO IO = new InMemoryFileIO();

  @Test
  void concurrentKeyRegistration() {
    StandardEncryptionManager encryption = newEncryptionManager();
    Set<FileEncryptionKeys> registered = ConcurrentHashMap.newKeySet();

    ExecutorService executor = Executors.newFixedThreadPool(THREADS);
    try {
      Tasks.range(KEYS)
          .executeWith(executor)
          .run(
              i ->
                  registered.add(
                      encryption.registerKeyMetadata(
                          encryption.encrypt(IO.newOutputFile("file-" + i)).keyMetadata())));
    } finally {
      executor.shutdownNow();
    }

    Map<String, EncryptedKey> keys = encryption.encryptionKeys();
    for (FileEncryptionKeys fileKeys : registered) {
      assertThat(keys).containsKey(fileKeys.fileKey().keyId());
    }

    // concurrent writers share one key encryption key
    assertThat(registered)
        .extracting(fileKeys -> fileKeys.keyEncryptionKey().keyId())
        .containsOnly(encryption.keyEncryptionKeyID());
    assertThat(keys).hasSize(KEYS + 1);
  }

  @Test
  void serialization() throws IOException, ClassNotFoundException {
    KeyManagementClient kmsClient = new MutableKeyMapKMS();
    kmsClient.initialize(Map.of());
    StandardEncryptionManager encryption =
        new StandardEncryptionManager(List.of(), UnitestKMS.MASTER_KEY_NAME1, 16, kmsClient);
    FileEncryptionKeys fileKeys =
        encryption.registerKeyMetadata(encryption.encrypt(IO.newOutputFile("file")).keyMetadata());

    for (StandardEncryptionManager copy :
        List.of(
            TestHelpers.roundTripSerialize(encryption),
            TestHelpers.KryoHelpers.roundTripSerialize(encryption))) {
      assertThat(copy.encryptionKeys())
          .containsOnlyKeys(fileKeys.keyEncryptionKey().keyId(), fileKeys.fileKey().keyId());
    }
  }

  private static StandardEncryptionManager newEncryptionManager() {
    KeyManagementClient kmsClient = new UnitestKMS();
    kmsClient.initialize(Map.of());
    return new StandardEncryptionManager(List.of(), UnitestKMS.MASTER_KEY_NAME1, 16, kmsClient);
  }

  /** Kryo cannot deserialize the immutable key map of {@link UnitestKMS}. */
  public static class MutableKeyMapKMS extends MemoryMockKMS {
    @Override
    public void initialize(Map<String, String> properties) {
      this.masterKeys =
          Maps.newHashMap(Map.of(UnitestKMS.MASTER_KEY_NAME1, UnitestKMS.MASTER_KEY1));
    }
  }
}
