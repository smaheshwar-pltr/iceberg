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
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.junit.jupiter.api.Test;

public class TestStandardEncryptionManager {

  @Test
  public void testGeneratedKeyIsResolvableOnlyAfterPersistingIntoMetadata() {
    StandardEncryptionManager manager =
        (StandardEncryptionManager) EncryptionTestHelpers.createEncryptionManager();
    StandardEncryptionManager.ManifestListKeys generated =
        manager.generateManifestListKey(keyMetadata());

    // Keys live in metadata, not the generating manager.
    assertThat(manager.encryptionKeys()).isEmpty();

    // A manager built from the generated keys (as metadata would supply) resolves the manifest
    // list key.
    List<EncryptedKey> metadataKeys =
        Lists.newArrayList(generated.manifestListKey(), generated.newKeyEncryptionKey());
    StandardEncryptionManager rebuilt =
        (StandardEncryptionManager) EncryptionTestHelpers.createEncryptionManager(metadataKeys);
    assertThat(rebuilt.encryptedByKey(generated.manifestListKey().keyId())).isNotNull();
  }

  private static NativeEncryptionKeyMetadata keyMetadata() {
    return new StandardKeyMetadata(new byte[16], new byte[12]);
  }
}
