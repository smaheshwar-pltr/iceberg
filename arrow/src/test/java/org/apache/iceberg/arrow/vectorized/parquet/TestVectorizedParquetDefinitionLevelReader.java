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
package org.apache.iceberg.arrow.vectorized.parquet;

import static org.apache.arrow.vector.BaseLargeVariableWidthVector.OFFSET_WIDTH;
import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import org.apache.arrow.memory.RootAllocator;
import org.apache.arrow.vector.BigIntVector;
import org.apache.arrow.vector.LargeVarCharVector;
import org.apache.parquet.bytes.ByteBufferInputStream;
import org.apache.parquet.column.Dictionary;
import org.apache.parquet.column.Encoding;
import org.apache.parquet.io.api.Binary;
import org.junit.jupiter.api.Test;

public class TestVectorizedParquetDefinitionLevelReader {
  private static final int UNIX_EPOCH_JULIAN_DAY = 2_440_588;

  /**
   * The variable-width reader writes into a 64-bit-offset {@link LargeVarCharVector} rather than a
   * 32-bit {@code VarCharVector}. Using 64-bit offsets is what allows a single batch to hold more
   * than {@link Integer#MAX_VALUE} (~2GB) of variable-width data without overflowing the offset
   * buffer (see #9820). This drives the real plain-encoded read path and verifies both the bytes
   * and the cumulative 8-byte offsets the reader writes, exercising the same offset arithmetic the
   * accessors use to read values back. It does not write >2GB of data, which would be prohibitively
   * expensive; correct 64-bit cumulative offsets are the property that makes >2GB batches
   * representable.
   */
  @Test
  public void varWidthReaderWritesValuesAndCumulative64BitOffsets() {
    String[] values = {"", "a", "iceberg", new String(new char[4096]).replace('\0', 'x')};

    try (RootAllocator allocator = new RootAllocator();
        LargeVarCharVector vector = new LargeVarCharVector("s", allocator)) {
      vector.setInitialCapacity(values.length);
      vector.allocateNewSafe();

      VectorizedParquetDefinitionLevelReader definitionReader =
          new VectorizedParquetDefinitionLevelReader(1, 1, false);
      VectorizedParquetDefinitionLevelReader.VarWidthReader varWidthReader =
          definitionReader.varWidthReader();

      VectorizedPlainValuesReader valuesReader = new VectorizedPlainValuesReader();
      valuesReader.initFromPage(values.length, ByteBufferInputStream.wrap(plainEncode(values)));

      for (int i = 0; i < values.length; i++) {
        varWidthReader.nextVal(vector, i, valuesReader, /* typeWidth */ -1, /* byteArray */ null);
      }
      vector.setValueCount(values.length);

      // Read values back the way the accessors do: via 8-byte offsets in the offset buffer and the
      // data buffer, rather than LargeVarCharVector#get (which additionally consults the validity
      // buffer that Iceberg does not always maintain).
      long expectedOffset = 0;
      for (int i = 0; i < values.length; i++) {
        byte[] expectedBytes = values[i].getBytes(StandardCharsets.UTF_8);
        long start = vector.getOffsetBuffer().getLong((long) i * OFFSET_WIDTH);
        long end = vector.getOffsetBuffer().getLong((long) (i + 1) * OFFSET_WIDTH);
        assertThat(start)
            .as("row %s should start at the running byte offset", i)
            .isEqualTo(expectedOffset);
        assertThat(end - start)
            .as("row %s should span exactly its byte length", i)
            .isEqualTo(expectedBytes.length);

        byte[] actualBytes = new byte[(int) (end - start)];
        vector.getDataBuffer().getBytes(start, actualBytes, 0, actualBytes.length);
        assertThat(new String(actualBytes, StandardCharsets.UTF_8))
            .as("row %s should round-trip through the large vector", i)
            .isEqualTo(values[i]);

        expectedOffset += expectedBytes.length;
      }
    }
  }

  /** Encodes strings as Parquet PLAIN byte arrays: a 4-byte little-endian length then the bytes. */
  private static ByteBuffer plainEncode(String... values) {
    int size = 0;
    for (String value : values) {
      size += Integer.BYTES + value.getBytes(StandardCharsets.UTF_8).length;
    }

    ByteBuffer buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
    for (String value : values) {
      byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
      buffer.putInt(bytes.length);
      buffer.put(bytes);
    }

    buffer.flip();
    return buffer;
  }

  @Test
  public void timestampInt96ReaderPackedDictionaryDecodeDecodesRowsCorrectly() {
    try (RootAllocator allocator = new RootAllocator();
        BigIntVector vector = new BigIntVector("ts", allocator)) {
      vector.allocateNew(2);
      vector.set(0, -1L);
      vector.set(1, -1L);

      VectorizedParquetDefinitionLevelReader definitionReader =
          new VectorizedParquetDefinitionLevelReader(1, 1, false);
      VectorizedDictionaryEncodedParquetValuesReader dictionaryReader =
          new VectorizedDictionaryEncodedParquetValuesReader(1, false);

      dictionaryReader.mode = BaseVectorizedParquetValuesReader.Mode.PACKED;
      dictionaryReader.currentCount = 2;
      dictionaryReader.packedValuesBuffer[0] = 0;
      dictionaryReader.packedValuesBuffer[1] = 1;

      Dictionary dictionary =
          new Dictionary(Encoding.PLAIN_DICTIONARY) {
            @Override
            public int getMaxId() {
              return 1;
            }

            @Override
            public Binary decodeToBinary(int id) {
              if (id == 0) {
                return int96Binary(111_111L);
              } else if (id == 1) {
                return int96Binary(222_222L);
              }

              throw new IllegalArgumentException("Unexpected dictionary id: " + id);
            }
          };

      VectorizedParquetDefinitionLevelReader.TimestampInt96Reader timestampReader =
          definitionReader.timestampInt96Reader();

      timestampReader.nextDictEncodedVal(
          vector,
          0,
          dictionaryReader,
          dictionary,
          BaseVectorizedParquetValuesReader.Mode.PACKED,
          1,
          null,
          Long.BYTES);
      timestampReader.nextDictEncodedVal(
          vector,
          1,
          dictionaryReader,
          dictionary,
          BaseVectorizedParquetValuesReader.Mode.PACKED,
          1,
          null,
          Long.BYTES);

      vector.setValueCount(2);

      assertThat(vector.get(0))
          .as("row 0 should receive the first decoded timestamp")
          .isEqualTo(111_111L);
      assertThat(vector.get(1))
          .as("row 1 should receive the second decoded timestamp")
          .isEqualTo(222_222L);
    }
  }

  private static Binary int96Binary(long micros) {
    long timeOfDayNanos = micros * 1_000L;
    byte[] bytes =
        ByteBuffer.allocate(12)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(timeOfDayNanos)
            .putInt(UNIX_EPOCH_JULIAN_DAY)
            .array();
    return Binary.fromConstantByteArray(bytes);
  }
}
