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
package org.apache.iceberg.aws.s3;

import java.io.IOException;
import java.io.UncheckedIOException;
import org.apache.iceberg.encryption.NativeFileCryptoParameters;
import org.apache.iceberg.encryption.NativelyEncryptedFile;
import org.apache.iceberg.exceptions.AlreadyExistsException;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.io.PositionOutputStream;
import org.apache.iceberg.metrics.MetricsContext;
import software.amazon.awssdk.services.s3.S3AsyncClient;
import software.amazon.awssdk.services.s3.S3Client;

public class S3OutputFile extends BaseS3File implements OutputFile, NativelyEncryptedFile {
  private NativeFileCryptoParameters nativeEncryptionParameters;

  static S3OutputFile fromLocation(
      String location, PrefixedS3Client client, MetricsContext metrics) {
    return new S3OutputFile(
        client.s3(),
        client.s3FileIOProperties().isS3AnalyticsAcceleratorEnabled() ? client.s3Async() : null,
        new S3URI(location, client.s3FileIOProperties().bucketToAccessPointMapping()),
        client.s3FileIOProperties(),
        metrics);
  }

  S3OutputFile(
      S3Client client,
      S3AsyncClient asyncClient,
      S3URI uri,
      S3FileIOProperties s3FileIOProperties,
      MetricsContext metrics) {
    super(client, asyncClient, uri, s3FileIOProperties, metrics);
  }

  /**
   * Create an output stream for the specified location if the target object does not exist in S3.
   *
   * <p>By default, the object's existence is checked when this method is called. When {@link
   * S3FileIOProperties#WRITE_CONDITIONAL_CREATE_ENABLED} is enabled, the upload is conditional on
   * the object not existing and {@link AlreadyExistsException} is thrown when the stream is closed.
   *
   * @return output stream
   */
  @Override
  public PositionOutputStream create() {
    if (s3FileIOProperties().isWriteConditionalCreateEnabled()) {
      return newStream(true);
    } else if (!exists()) {
      return createOrOverwrite();
    } else {
      throw new AlreadyExistsException("Location already exists: %s", uri());
    }
  }

  @Override
  public PositionOutputStream createOrOverwrite() {
    return newStream(false);
  }

  private PositionOutputStream newStream(boolean failIfExists) {
    try {
      return new S3OutputStream(client(), uri(), s3FileIOProperties(), metrics(), failIfExists);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to create output stream for location: " + uri(), e);
    }
  }

  @Override
  public InputFile toInputFile() {
    return new S3InputFile(client(), asyncClient(), uri(), null, s3FileIOProperties(), metrics());
  }

  @Override
  public NativeFileCryptoParameters nativeCryptoParameters() {
    return nativeEncryptionParameters;
  }

  @Override
  public void setNativeCryptoParameters(NativeFileCryptoParameters nativeCryptoParameters) {
    this.nativeEncryptionParameters = nativeCryptoParameters;
  }
}
