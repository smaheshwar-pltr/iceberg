/*
 *
 *  * Licensed to the Apache Software Foundation (ASF) under one
 *  * or more contributor license agreements.  See the NOTICE file
 *  * distributed with this work for additional information
 *  * regarding copyright ownership.  The ASF licenses this file
 *  * to you under the Apache License, Version 2.0 (the
 *  * "License"); you may not use this file except in compliance
 *  * with the License.  You may obtain a copy of the License at
 *  *
 *  *   http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing,
 *  * software distributed under the License is distributed on an
 *  * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  * KIND, either express or implied.  See the License for the
 *  * specific language governing permissions and limitations
 *  * under the License.
 *
 */

package org.apache.iceberg.encryption;

import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.util.ByteBuffers;

public enum UnitTestEncryptionManager implements EncryptionManager {
    INSTANCE;

    @Override
    public InputFile decrypt(EncryptedInputFile encrypted) {
        if (encrypted instanceof NativeEncryptionInputFile) {
            return (NativeEncryptionInputFile) encrypted;
        }

        return new UnitTestDecryptedInputFile(encrypted);
    }

    @Override
    public EncryptedOutputFile encrypt(OutputFile rawOutput) {
        return new UnitTestEncryptedOutputFile(rawOutput);
    }

    private static class UnitTestEncryptedOutputFile implements NativeEncryptionOutputFile {
        private final OutputFile plainOutputFile;
        private StandardKeyMetadata lazyKeyMetadata = null;
        private OutputFile lazyEncryptingOutputFile = null;

        UnitTestEncryptedOutputFile(OutputFile plainOutputFile) {
            this.plainOutputFile = plainOutputFile;
        }

        @Override
        public StandardKeyMetadata keyMetadata() {
            if (null == lazyKeyMetadata) {
                this.lazyKeyMetadata = KeyMetadataServiceClient.INSTANCE.generateStandardKeyMetadata(plainOutputFile);
            }

            return lazyKeyMetadata;
        }

        @Override
        public OutputFile encryptingOutputFile() {
            if (null == lazyEncryptingOutputFile) {
                this.lazyEncryptingOutputFile =
                        new AesGcmOutputFile(
                                plainOutputFile,
                                ByteBuffers.toByteArray(keyMetadata().encryptionKey()),
                                ByteBuffers.toByteArray(keyMetadata().aadPrefix()));
            }

            return lazyEncryptingOutputFile;
        }

        @Override
        public OutputFile plainOutputFile() {
            return plainOutputFile;
        }
    }

    private enum KeyMetadataServiceClient {
        INSTANCE;

        public StandardKeyMetadata generateStandardKeyMetadata(OutputFile ignored) {
            // TODO: Persist.
            return new StandardKeyMetadata(
                    new byte[] { 0x01, 0x02, 0x03, 0x04 },
                    new byte[] { 0x05, 0x06, 0x07, 0x08 });
        }
    }
}
