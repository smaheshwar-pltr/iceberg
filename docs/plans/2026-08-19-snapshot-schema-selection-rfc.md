<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

# Make exact snapshot selection explicit

Status: Draft for discussion

## Decision requested

Iceberg uses `useSnapshot(long)` for two operations with different schema requirements:

1. An exact read selects a snapshot's files and schema.
2. A consistency pin freezes a file set after an engine has captured a table schema.

Agree on these two intents before changing the current heuristic. The fork prototype uses one opt-in exact selector:

```java
atSnapshot(long snapshotId)
```

Keep `useSnapshot` unchanged and undeprecated. The prototype does not settle whether Iceberg should adopt this name, change `useSnapshot` later, add an explicit pin API, or replace both operations with a larger API family. The API decision should precede an implementation contribution because any accepted method becomes a permanent compatibility commitment.

Existing failing `useSnapshot` calls are not fixed automatically. Callers get exact semantics only after moving to `atSnapshot`.

## Current failures

### The current snapshot can outlive its schema

Partitioning is not required. This unpartitioned-table sequence fails on main:

```java
Snapshot snapshot = table.currentSnapshot(); // schema A contains data
table.updateSchema().deleteColumn("data").commit(); // schema B, no new snapshot

table.newScan()
    .useSnapshot(snapshot.snapshotId())
    .filter(Expressions.equal("data", "xyz"))
    .planFiles();
```

`useSnapshot` selects schema A, but [`SnapshotScan.specs()` returns specs bound to schema B](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/core/src/main/java/org/apache/iceberg/SnapshotScan.java#L83-L101) because the selected snapshot is still current. Planning throws `Cannot find field 'data'`. The same scenario was [identified during review of #17735](https://github.com/apache/iceberg/pull/17735#discussion_r3824081782).

### `main` can be empty while another branch has a snapshot

Iceberg allows a table to have no current snapshot on `main` while another branch points to a snapshot. If the table schema has evolved since that snapshot, selecting it by ID chooses the snapshot schema but `SnapshotScan.specs()` returns table specs because `currentSnapshot()` is null. Filter planning then fails with the [same field-binding error](https://github.com/apache/iceberg/pull/17735#discussion_r3817443288). This case is tracked by [#17734](https://github.com/apache/iceberg/issues/17734).

Both failures come from inferring schema intent from the state of `main`.

### REST server-side planning has a related boundary bug

This applies only to REST server-side planning, not normal client-side planning through a REST catalog.

For a historical snapshot, the handler can [plan with the selected snapshot](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/core/src/main/java/org/apache/iceberg/rest/CatalogHandlers.java#L834-L849) but [serialize tasks with current table specs](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/core/src/main/java/org/apache/iceberg/rest/CatalogHandlers.java#L852-L884). The client may [decode with specs captured when its scan was created](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/core/src/main/java/org/apache/iceberg/rest/RESTTableScan.java#L92-L115). Schema evolution can therefore make planning, serialization, and decoding disagree.

A focused main-branch reproduction uses an identity partition field, evolves its type, commits a later snapshot, then plans the earlier snapshot. Task serialization fails with `Invalid default long value: 1`. Async results and task pages have the same risk because each handler reloads current table specs.

The fork prototype does not repair or regress this path. REST server-side planning remains unsupported by `atSnapshot` until the wire contract is explicit.

## Why one method currently has two meanings

Spark demonstrates both intents. It [captures a schema and snapshot when it creates a scan builder](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/spark/v4.1/spark/src/main/java/org/apache/iceberg/spark/source/SparkScanBuilder.java#L82-L114), then [calls `useSnapshot` for current-table pins and time travel](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/spark/v4.1/spark/src/main/java/org/apache/iceberg/spark/source/SparkScanBuilder.java#L339-L360). A normal main-table read is a pin because [`shouldPinSnapshot()` is true for `BaseTable`](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/spark/v4.1/spark/src/main/java/org/apache/iceberg/spark/source/SparkScanBuilder.java#L395-L400).

The [suggested schema-ID comparison](https://github.com/apache/iceberg/pull/17735#discussion_r3824081782) fixes exact reads but cannot distinguish them from pins. Testing that change against Spark 4.1 Core made current-table scans lose fields added after their pinned snapshot or lose the expected runtime filter. Core rewrite actions and Flink maintenance code also pin captured snapshots.

In-tree dependence on pin semantics is proven. Out-of-tree dependence is possible but has not been measured.

## Options

| Option | Benefit | Cost |
| --- | --- | --- |
| Change `useSnapshot` to exact semantics and add an explicit pin operation | Fixes existing exact-read callers without opt-in; yields the smallest final API | Requires a pin API and a 1.x deprecation cycle before the 2.0 change; callers must migrate |
| Add only `atSnapshot(long)` now | Smallest additive API; fixes both local cases for callers that opt in | Creates permanent public surface while leaving `useSnapshot`, timestamp, tag, metadata, and REST behavior unchanged |
| Add `atSnapshot(long)` and `atSnapshot(long, Schema)`, then deprecate `useSnapshot` | Represents exact reads and pins without changing legacy behavior | Adds a larger surface before metadata, REST, and external adoption are resolved |
| Remove only the empty-`main` guard | Smallest tactical fix for #17734 | Leaves the current-snapshot failure and the ambiguous model |
| Keep the current API | No compatibility work | Both exact-read failures remain |

A package-private pin API is not sufficient. Pin callers span API, Core, Spark, and Flink and operate through public `TableScan` or `BatchScan` interfaces.

## Recommended contribution order

First file the current-snapshot bug with its format-version coverage and link this proposal. Keep #17734 and #17735 focused on the empty-`main` case.

Next, discuss the selector contract before asking maintainers to review implementation code. The discussion must settle at least the method name, which scan families opt in, how timestamp and ref selection relate to exact selection, and whether an explicit consistency-pin operation belongs in the eventual API.

Only then submit the implementation. The fork prototype below exists to prove that the smallest proposed contract is implementable without changing `useSnapshot`; it is not the recommended first upstream PR.

## Prototype implementation after agreement

Add a default method to [`TableScan`](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/api/src/main/java/org/apache/iceberg/TableScan.java#L30-L38):

```java
default TableScan atSnapshot(long snapshotId) {
  throw new UnsupportedOperationException("Exact snapshot selection is not supported");
}
```

Add the corresponding default to `BatchScan` and delegate it in [`BatchScanAdapter`](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/api/src/main/java/org/apache/iceberg/BatchScanAdapter.java#L48-L60).

`BatchScanAdapter` has an additional concrete-class compatibility surface. An
already-compiled subclass's public exact-descriptor method still overrides the
new delegate. A private exact-descriptor method is ignored, so the delegate
runs. For a call through `BatchScan`, a protected or package-private
exact-descriptor method is selected but fails with `IllegalAccessError`; an
`invokevirtual` call resolved to `BatchScanAdapter` can instead dispatch to that
subclass method. A covariant method without the previously unnecessary bridge
is bypassed until recompilation adds that bridge. An incompatible same-name
method can remain irrelevant in the old binary but prevent recompilation. A
default from another interface with the same JVM descriptor that the subclass
previously inherited is displaced because the new concrete superclass method
wins. Adapter subclasses therefore require the same contract audit as direct
`BatchScan` implementations, plus this concrete-method dispatch audit.

Implement `atSnapshot` in a package-private `LocalDataTableScan` created by `BaseTable`. It selects the snapshot schema and marks the local scan as exact without adding state to the public generated `TableScanContext`. `SnapshotScan` then binds specs to that schema even when the snapshot is current or `main` is empty. After loading the selected snapshot's manifest lists as normal, planning rebinds only the spec IDs used by those data and delete manifests. It does not pre-read or filter manifest contents. A legacy snapshot with no recorded schema ID fails because Iceberg cannot provide exact semantics. Keep `useSnapshot` and its state-based guards unchanged.

Leave the new method unsupported for REST server-side planning, incremental scans, metadata scans, position-delete scans, and external implementations that do not override it. The REST and incremental `DataTableScan` subclasses reject it explicitly. Other `DataTableScan` subclasses inherit the interface default and remain unsupported. A pre-existing public method overrides the new default in an old binary only when it has the interface method's exact JVM descriptor. A private exact-descriptor method is ignored and reaches the default. For a call through the new interface, a protected or package-private exact-descriptor method is selected but fails with `IllegalAccessError`. A public covariant method gains the required bridge after recompilation, but an old binary without that bridge still reaches the default. Either implementation must be audited against the new contract. Do not migrate generic engines or deprecate any API in the prototype. Default methods preserve ordinary linkage, and implementations that inherit the default fail clearly rather than silently using legacy semantics.

`DataTableScan` is public, has a protected constructor, and is designed for subclassing. Implementing exact selection there would silently opt unknown subclasses into state that their planning code may ignore. Putting that state in `TableScanContext` is also not internal: Immutables generates public methods on the shipped `ImmutableTableScanContext` and its builder. The package-private subtype keeps the marker private to Core's local scan and preserves the stronger opt-in boundary. `BaseTable.newScan()` consequently returns a `LocalDataTableScan` instance instead of an exact `DataTableScan` instance, but the declared type, `instanceof DataTableScan`, and casts remain unchanged. Exact class inspection observes the new subtype, and the inherited `toString()` prefix changes from `DataTableScan` to `LocalDataTableScan`. The scan is not serializable, and no in-tree caller depends on either representation. This narrow concrete-type compatibility cost is preferable to changing the behavior of a public extension surface.

An exact selection cannot be followed by another snapshot, timestamp, or ref selector. Existing selectors already reject overrides, except for a legacy `useSnapshot(...).useRef("main")` fast path. The prototype rejects the equivalent exact-selection chain without changing that existing edge behavior.

The corrected exact-read call is:

```java
table.newScan()
    .atSnapshot(snapshot.snapshotId())
    .filter(Expressions.equal("data", "xyz"))
    .planFiles();
```

Tests cover both failures with bucket partitioning, referenced specs whose source field was dropped, specs used only by delete manifests, unreferenced later specs, `BatchScanAdapter` delegation, task schemas and residuals, legacy `useSnapshot` pin behavior, selector override rejection, and clear rejection by unsupported scans. The change must pass RevAPI.

## Compatibility accounting

| Boundary | Effect of the prototype |
| --- | --- |
| Existing source implementors | Ordinary implementations need no change because both additions are default methods. On recompilation, a pre-existing public covariant `atSnapshot(long)` declaration overrides the new default and receives a compiler-generated bridge. An incompatible declaration, a weaker-access declaration, or conflicting inherited defaults can fail recompilation until the clash is resolved. |
| Existing binaries | Ordinary implementations and existing callers continue to link. A pre-existing public exact-descriptor method is successfully invoked by a caller compiled against the new interface. A private exact-descriptor method is ignored, so the caller reaches the unsupported default. A protected or package-private exact-descriptor method is selected but fails with `IllegalAccessError`. An old covariant method has no bridge for the previously absent interface method, so such a caller also reaches the unsupported default until the implementation is recompiled. A type that inherits conflicting defaults can fail when the new method is invoked, as allowed by JLS 13.5.7. Code compiled against the new method also requires a runtime that contains it. |
| Existing scan planning | `useSnapshot`, `asOfTime`, and `useRef` keep their current schema and spec rules. Exact behavior requires a new call, and another selector cannot override it. The concrete-type effects below remain observable. |
| Out-of-tree implementations | Direct `TableScan` and `BatchScan` implementations inherit a clear `UnsupportedOperationException` unless they override the new method. A pre-existing public exact-descriptor method overrides immediately. A private exact-descriptor method is ignored and reaches the default, while a protected or package-private exact-descriptor method fails with `IllegalAccessError` when called through the interface. A public covariant method overrides after recompilation adds its bridge. Either public method must be audited for the new contract. |
| `BatchScanAdapter` subclasses | The new concrete delegate wins over unrelated interface defaults with the same JVM descriptor that an existing subclass inherited. An old public exact-descriptor method still overrides it. A private exact-descriptor method is ignored, so the delegate runs. For a call through `BatchScan`, a protected or package-private exact-descriptor method is selected but fails with `IllegalAccessError`; an `invokevirtual` call resolved to `BatchScanAdapter` can instead dispatch to that subclass method. An old covariant method is bypassed until recompilation adds a bridge, and a source-incompatible declaration can prevent recompilation. |
| `DataTableScan` subclasses | Subclasses inherit the unsupported interface default unless they provide a public exact-descriptor override under the invocation rules above. Known REST and incremental subclasses reject explicitly with contextual messages. |
| Concrete scan type | `BaseTable.newScan()` returns a package-private `LocalDataTableScan` subtype. `instanceof DataTableScan` and casts still work; exact class inspection and the inherited `toString()` prefix observe the change. |
| Engines | Spark, Flink, MapReduce, and generic readers do not migrate. Existing current-table pins remain pins. |
| REST | Server-side planning rejects locally before a request. There is no OpenAPI, request, response, task, or pagination change. Normal client-side planning through a REST catalog continues to use local Core scans. |
| Table format | No format or metadata change. The prototype passes formats 1 through 4. A legacy snapshot without `schema-id` is rejected because exact binding cannot be guaranteed. |

RevAPI accepts the interface additions. This establishes mechanical API compatibility, not agreement that the new abstraction is complete.

## Follow-up decisions

The first PR leaves these choices open:

- Whether a 1.x release adds a named pin operation and deprecates `useSnapshot`, allowing 2.0 to redefine or remove it, or whether `useSnapshot` remains supported alongside two explicit operations.
- Whether timestamp and tag reads move to the exact path. Their intent is exact, but they currently use the legacy implementation.
- How snapshot-selectable metadata and position-delete scans preserve their derived schemas.
- When generic engines can call the new method without breaking valid external scan implementations.

REST server-side planning needs a separate protocol decision. Credible options are:

1. Add exact-only support with a new request discriminator, a server-derived snapshot schema, an acknowledgement, and stable schema-bound specs for every result and task page.
2. Carry a full binding schema to support both exact reads and arbitrary pins, including schemas removed from current metadata.
3. Repair legacy task serialization independently while keeping legacy schema semantics.

Old requests must stay on the legacy path. A new client must detect an old server before decoding tasks, and a new server must preserve one accepted binding context across synchronous results, asynchronous results, and task pages.

## Compatibility and implementation constraints

[`iceberg-api` requires a major-version deprecation cycle](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/site/docs/contribute.md#L148-L160). New interface methods need [default implementations](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/site/docs/contribute.md#L280-L292).

Not every `SnapshotScan` is a data-table scan. Metadata and position-delete scans use schemas derived from the base table, so a generic implementation must not replace their schema with the snapshot's data schema. Incremental and all-snapshot metadata scans already reject snapshot selection. The unrelated [`PartitionStatisticsScan.useSnapshot`](https://github.com/apache/iceberg/blob/ebebc345624a8f51c2e9caf4bb5624c79fb2656b/api/src/main/java/org/apache/iceberg/PartitionStatisticsScan.java#L25-L34) is outside this proposal.

If a later pin API carries a `Schema`, its contract must cover metadata cleanup and schema-ID reuse. If a later REST protocol accepts that schema from a client, it must also define validation and trust.

## Evidence and history

- [Incorrect schema used when using time travel](https://github.com/apache/iceberg/issues/11162)
- [Core: Use time-travel schema when resolving partition spec in scan](https://github.com/apache/iceberg/pull/13301)
- [Core: Fix failure when finding a column during time travel](https://github.com/apache/iceberg/pull/14438)
- [Core: Schema for a branch should return table schema](https://github.com/apache/iceberg/pull/9131)
- [Core: Use snapshot schema when main has no current snapshot](https://github.com/apache/iceberg/pull/17735)
- [Read schema to use during time travel](https://lists.apache.org/thread/2k74yykfgm88ndoghs5nhmsot09ngdzv)
