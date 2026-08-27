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

import java.util.function.Supplier;
import org.apache.iceberg.io.FileIO;

/** API for configuring a batch scan. */
public interface BatchScan extends Scan<BatchScan, ScanTask, ScanTaskGroup<ScanTask>> {
  /**
   * Returns the {@link Table} from which this scan loads data.
   *
   * @return this scan's table
   */
  Table table();

  /**
   * Create a new {@link BatchScan} from this scan's configuration that will use a snapshot with the
   * given ID.
   *
   * @param snapshotId a snapshot ID
   * @return a new scan based on this with the given snapshot ID
   * @throws IllegalArgumentException if the snapshot cannot be found
   * @deprecated since 1.12.0, will be removed in 2.0.0; use {@link #useSnapshot(long,
   *     BindingSchema)} to state which schema the scan should resolve names against.
   */
  @Deprecated
  BatchScan useSnapshot(long snapshotId);

  /**
   * Create a new {@link BatchScan} from this scan's configuration that will use a snapshot with the
   * given ID, resolving names and types against the given {@link BindingSchema}.
   *
   * @param snapshotId a snapshot ID
   * @param bindingSchema which schema the scan should resolve names and types against
   * @return a new scan based on this with the given snapshot ID and binding schema
   * @throws IllegalArgumentException if the snapshot cannot be found
   * @throws UnsupportedOperationException if this scan cannot use the given binding schema
   */
  default BatchScan useSnapshot(long snapshotId, BindingSchema bindingSchema) {
    throw new UnsupportedOperationException("Selecting a binding schema is not supported");
  }

  /**
   * Create a new {@link BatchScan} from this scan's configuration that will use the given
   * reference.
   *
   * @param ref a reference
   * @return a new scan based on this with the given reference
   * @throws IllegalArgumentException if the reference with the given name could not be found
   */
  BatchScan useRef(String ref);

  /**
   * Create a new {@link BatchScan} from this scan's configuration that will use the most recent
   * snapshot as of the given time in milliseconds on the branch in the scan or main if no branch is
   * set.
   *
   * @param timestampMillis a timestamp in milliseconds
   * @return a new scan based on this with the current snapshot at the given time
   * @throws IllegalArgumentException if the snapshot cannot be found or time travel is attempted on
   *     a tag
   * @deprecated since 1.12.0, will be removed in 2.0.0; use {@link #asOfTime(long, BindingSchema)}
   *     to state which schema the scan should resolve names against.
   */
  @Deprecated
  BatchScan asOfTime(long timestampMillis);

  /**
   * Create a new {@link BatchScan} from this scan's configuration that will use the most recent
   * snapshot as of the given time in milliseconds, resolving names and types against the given
   * {@link BindingSchema}.
   *
   * @param timestampMillis a timestamp in milliseconds
   * @param bindingSchema which schema the scan should resolve names and types against
   * @return a new scan based on this with the snapshot at the given time and binding schema
   * @throws IllegalArgumentException if the snapshot cannot be found
   * @throws UnsupportedOperationException if this scan cannot use the given binding schema
   */
  default BatchScan asOfTime(long timestampMillis, BindingSchema bindingSchema) {
    throw new UnsupportedOperationException("Selecting a binding schema is not supported");
  }

  /**
   * Returns the {@link Snapshot} that will be used by this scan.
   *
   * <p>If the snapshot was not configured using {@link #asOfTime(long)} or {@link
   * #useSnapshot(long)}, the current table snapshot will be used.
   *
   * @return the Snapshot this scan will use
   */
  Snapshot snapshot();

  /** Returns the {@link FileIO} instance to use when reading data files for this scan. */
  @Override
  default Supplier<FileIO> fileIO() {
    return table()::io;
  }
}
