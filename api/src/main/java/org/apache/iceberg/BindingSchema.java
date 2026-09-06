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

/**
 * The schema a scan resolves names and types against.
 *
 * <p>Selecting a snapshot by ID has two uses that need different schemas. An exact read of a
 * historical snapshot must resolve the caller's column names in the schema that snapshot recorded.
 * A consistency pin, where an engine has already captured a schema and only wants the file set
 * frozen, must keep resolving names in the table's schema. A snapshot ID alone cannot distinguish
 * them, so the caller states which schema applies.
 *
 * <p>The binding schema governs everything a scan resolves by name or type: the schema the row
 * filter binds against, the schema partition specs are bound to (and therefore the types used to
 * evaluate partition predicates and residuals), the schema {@code select(String...)} resolves
 * column names in, the default projection when neither {@code select} nor {@code project} was
 * called, and the schema serialized into scan tasks.
 *
 * <p>It is not the output projection. {@code project} and {@code select} apply independently and
 * still override what a scan returns.
 *
 * <p>Reading is resolved by field ID, so the binding schema does not change how files are decoded.
 * It must therefore belong to the table's schema evolution history; the two values here always do.
 */
public enum BindingSchema {
  /**
   * The schema recorded by the selected snapshot, for reading a table as it was at that snapshot.
   *
   * <p>Snapshots written before Iceberg recorded a schema ID have none. Those fall back to the
   * table's current schema, which cannot be correct if the schema has since evolved.
   */
  SNAPSHOT,

  /**
   * The scan's table schema, left unchanged by the selection, for freezing a file set without
   * moving the schema.
   *
   * <p>This is what selecting a branch already does, addressed by snapshot ID instead of by ref.
   */
  TABLE
}
