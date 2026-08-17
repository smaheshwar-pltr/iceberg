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

# RFC: Preserve manifest-list keys across concurrent commits

## Decision

Proceed with three ordered PRs:

1. [PR 1](https://github.com/smaheshwar-pltr/iceberg/pull/25) protects shared
   `StandardEncryptionManager` key state.
2. [PR 2](https://github.com/smaheshwar-pltr/iceberg/pull/27) commits each snapshot with the wrapped
   keys for its manifest list. This fixes the direct concurrent-append failure.
3. [PR 3](https://github.com/smaheshwar-pltr/iceberg/pull/28) scopes temporary Hive operations to
   staged metadata and rebuilds them before transaction replay.

PR 3 is not needed for PR 2's direct concurrent-append test to pass. It is nevertheless required
before release because PR 2 alone exposes a deterministic encrypted-transaction regression. Review
the PRs separately, merge them in order, and treat the complete stack as the release unit.

Keep the existing manifest-list key insertion API compatible. Do not adopt the breaking immutable-
manager redesign. Treat the missing key as a correctness and data-availability bug, not as a
security vulnerability.

## Diagnosis

Hive is the only built-in catalog path that supplies standard table encryption. A manifest-list
writer adds wrapped key records to the encryption manager captured for its write attempt and returns
a key ID. `SnapshotProducer` places that ID in the snapshot. Hive previously copied keys later from
whichever manager `HiveTableOperations` held at commit time.

A competing commit can refresh the shared operations and replace that manager. The first writer can
then mint into its retired manager while Hive commits metadata from the replacement. The committed
snapshot references a key absent from `metadata.encryption-keys` and cannot be read.

More Hive locking does not make the separately owned mint and metadata commit atomic. The fix belongs
in `SnapshotProducer`, where the write-attempt manager, snapshot, and `TableMetadata.Builder` are in
scope together.

The trust model is unchanged. Hive still obtains the table master-key ID from the catalog and still
checks metadata integrity. Core adds only already-wrapped key records to the metadata update that
adds their snapshot.

## PR boundaries and evidence

### PR 1: Protect shared manager state

- Serialize KEK creation, key insertion and lookup, registry snapshots, and Java serialization.
- Return detached registry values and copy mutable key buffers and properties only when ownership
  crosses the constructor, KMS, or registry boundary.
- Pin the pre-change Java serialization UID.

The exact latch-controlled concurrent-mint test fails on the immediate base because two callers
wrap two KEKs instead of sharing one. It passes on PR 1. Other focused tests force registry snapshot
and serialization attempts during a blocked mint, require non-empty state with no MLK missing its
wrapping KEK, and verify the mutable-input boundaries. A KEK without an MLK is valid while the first
MLK is still being encrypted.

### PR 2: Commit keys with the snapshot

- Retain the manager used for the current manifest-list write attempt.
- Take one detached point-in-time registry snapshot through the existing
  `EncryptionUtil.encryptionKeys` path, validate the referenced manifest-list key and its wrapping
  KEK, and retain only that pair. No new public API is added.
- Add the pair to the same metadata update that adds the snapshot and clear attempt-local state on
  retry.
- Remove Hive's commit-time copy of ambient manager keys and refresh-time carry-forward of
  uncommitted manager state. Refreshed encryption state now comes from committed metadata.

The registry snapshot is O(number of retained keys) once per encrypted snapshot commit. A targeted
cross-package lookup would avoid that cost but would require new public API; this stack favors API
compatibility and bounded review scope.

`TestTableEncryption.concurrentAppendsPreserveManifestListKeys` uses one shared Hive-backed `Table`,
two fast appends, and two KMS unwrap barriers to force the manager-replacement interleaving. It adds
no retry property or stress-only configuration. The exact test fails on `main` with a missing
manifest-list key and passes on PR 2. It then reloads the table, plans every snapshot, and verifies
both appends.

The core harness separately covers ordinary, stage-only, and retried `SnapshotProducer` branches.
It verifies metadata output with a test-injected manager; it is not evidence that a non-Hive catalog
supports standard encryption.

### PR 3: Preserve staged encrypted transaction state

- Rebuild temporary operations after a transaction adopts refreshed metadata and before replay.
- Build Hive temporary encryption and `FileIO` lazily from the exact staged metadata represented by
  those operations.
- Keep the master-key trust anchor catalog-sourced for an existing table while taking wrapped keys
  and DEK length from staged metadata. A create transaction falls back to its staged key property
  because the catalog entry does not yet exist.

Measured against PR 2, before applying PR 3:

| Test | PR 2 | PR 3 | Purpose |
| --- | --- | --- | --- |
| Spark `transactionRebasePreservesManifestListKeys` | Fails: staged parent key is missing | Passes | Proves a second staged append survives an interleaved direct commit |
| Core `transactionRebasePreservesManifestListKeys` | Fails while replay reads the adopted parent | Passes | Proves temporary operations are reset before replay |
| Spark `stagedDataKeyLengthControlsTemporaryEncryption` | Fails: 16 bytes instead of staged 32 | Passes | Proves temporary encryption uses staged properties |
| Spark `encryptedCreateTransactionUsesStagedMetadata` | Passes | Passes | Preserves encrypted creation and verifies its MLK, KEK, and readable snapshot |
| Spark `catalogMasterKeyControlsTemporaryEncryption` | Passes | Passes | Preserves catalog master-key precedence over conflicting staged metadata |

The first Spark test also passes on `main`; its failure is the temporary regression introduced by
PR 2's removal of manager-only key carry-forward. This is why PR 3 must ship with PR 2 even though it
does not complete the direct concurrency fix.

## Steps to proceed

1. Finish local validation, independent review, and actionable CI on draft fork PRs 1 through 3.
2. Obtain human sign-off on the diagnosis, PR boundaries, and the explicit PR 2-to-PR 3 release
   dependency.
3. File one upstream issue titled **Concurrent commits to a v3 encrypted Hive table can omit a
   manifest-list key**. Include the deterministic two-append test and its main-fail/PR-2-pass result.
4. Open the three upstream PRs in order. Link the issue and full stack from every description. Mark
   PR 2's temporary transaction regression prominently in both PR 2 and PR 3, and merge PR 3 before
   any release containing PR 2.
5. File encrypted `rewrite_table_path` as a separate deterministic issue. It is unrelated to
   concurrent commit ownership.
6. Keep commit-service serialization separate. It can remove a trigger but cannot make a snapshot
   and its key one metadata update.
7. If the full fix cannot reach a maintained release promptly, consider a Hive fail-closed guard
   that rejects newly added snapshots missing their linked keys. That contains corruption but is not
   the fix.

## Known limits

- A custom REST-backed standard-encryption implementation may return `CommitStateUnknownException`
  when an `AddSnapshot` carries companion `AddEncryptionKey` updates because unknown-state
  reconciliation does not classify that update shape. Built-in standard encryption is Hive-only, so
  this is a forward-compatibility limit rather than part of the reported bug.
- Encrypted `rewrite_table_path` needs either explicit rejection or a complete encrypted rewrite.
- Hive publishes several refresh fields separately. Do not broaden this stack without a
  deterministic failure demonstrating a remaining user-visible problem.

## Changes since the previous RFC

- Replaced the obsolete stress-test claim with the committed deterministic two-append test.
- Removed the nonexistent targeted lookup helper and documented the existing detached O(n) registry
  snapshot and its API-compatibility tradeoff.
- Made PR 2's temporary encrypted-transaction regression and PR 3's release requirement explicit.
- Added the complete PR 2/PR 3 evidence matrix, including which tests pass on both sides.
- Strengthened manager-overlap and encrypted-create assertions so they cannot pass vacuously or with
  plaintext output.
