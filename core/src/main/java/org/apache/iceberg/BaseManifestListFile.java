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
package org.apache.iceberg;

import java.io.Serializable;
import java.nio.ByteBuffer;
import org.apache.iceberg.encryption.Ciphers;
import org.apache.iceberg.encryption.EncryptionKeyMetadata;
import org.apache.iceberg.encryption.EncryptionManager;
import org.apache.iceberg.encryption.EncryptionUtil;
import org.apache.iceberg.encryption.KeyEncryptionKey;
import org.apache.iceberg.encryption.StandardEncryptionManager;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.util.ByteBuffers;

public class BaseManifestListFile implements ManifestListFile, Serializable {
  private final String location;
  private final String mdEncryptionKeyID;
  private final ByteBuffer encryptedKeyMetadata;
  private ByteBuffer keyMetadata;

  public BaseManifestListFile(
      String location,
      ByteBuffer keyMetadata,
      String mdEncryptionKeyID,
      ByteBuffer encryptedKeyMetadata) {
    this.location = location;
    this.keyMetadata = keyMetadata;
    this.encryptedKeyMetadata = encryptedKeyMetadata;
    this.mdEncryptionKeyID = mdEncryptionKeyID;
  }

  @Override
  public String location() {
    return location;
  }

  @Override
  public ByteBuffer keyMetadata() {
    return keyMetadata;
  }

  @Override
  public String metadataEncryptionKeyID() {
    return mdEncryptionKeyID;
  }

  @Override
  public ByteBuffer encryptedKeyMetadata() {
    return encryptedKeyMetadata;
  }

  public void setDecryptedKeyMetadata(ByteBuffer decryptedKeyMetadata) {
    this.keyMetadata = decryptedKeyMetadata;
  }

  static ManifestListFile create(
      String location, EncryptionManager em, EncryptionKeyMetadata keyMetadata, long length) {
    ByteBuffer manifestListKeyMetadata = null;
    String keyEncryptionKeyID = null;
    ByteBuffer encryptedManifestListKeyMetadata = null;

    // Encrypted manifest list
    if (keyMetadata != null && keyMetadata.buffer() != null) {
      manifestListKeyMetadata = EncryptionUtil.setFileLength(keyMetadata, length).buffer();

      Preconditions.checkState(
          em instanceof StandardEncryptionManager,
          "Can't get key encryption key for manifest lists - encryption manager %s is not instance of StandardEncryptionManager",
          em.getClass());
      KeyEncryptionKey kek = ((StandardEncryptionManager) em).currentKEK();
      Ciphers.AesGcmEncryptor manifestListMDEncryptor = new Ciphers.AesGcmEncryptor(kek.key());

      encryptedManifestListKeyMetadata =
          ByteBuffer.wrap(
              manifestListMDEncryptor.encrypt(
                  ByteBuffers.toByteArray(manifestListKeyMetadata), null));
      keyEncryptionKeyID = kek.id();
    }

    return new BaseManifestListFile(
        location, manifestListKeyMetadata, keyEncryptionKeyID, encryptedManifestListKeyMetadata);
  }
}
