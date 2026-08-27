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

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.iceberg.events.Listeners;
import org.apache.iceberg.events.ScanEvent;
import org.apache.iceberg.expressions.ExpressionUtil;
import org.apache.iceberg.io.CloseableIterable;
import org.apache.iceberg.metrics.DefaultMetricsContext;
import org.apache.iceberg.metrics.ImmutableScanReport;
import org.apache.iceberg.metrics.ScanMetrics;
import org.apache.iceberg.metrics.ScanMetricsResult;
import org.apache.iceberg.metrics.ScanReport;
import org.apache.iceberg.metrics.Timer;
import org.apache.iceberg.relocated.com.google.common.base.MoreObjects;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableMap;
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.apache.iceberg.relocated.com.google.common.collect.Maps;
import org.apache.iceberg.relocated.com.google.common.collect.Sets;
import org.apache.iceberg.types.TypeUtil;
import org.apache.iceberg.util.DateTimeUtil;
import org.apache.iceberg.util.SnapshotUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a common base class to share code between different BaseScan implementations that handle
 * scans of a particular snapshot.
 *
 * @param <ThisT> actual BaseScan implementation class type
 * @param <T> type of ScanTask returned
 * @param <G> type of ScanTaskGroup returned
 */
public abstract class SnapshotScan<ThisT, T extends ScanTask, G extends ScanTaskGroup<T>>
    extends BaseScan<ThisT, T, G> {

  private static final Logger LOG = LoggerFactory.getLogger(SnapshotScan.class);

  private ScanMetrics scanMetrics;

  protected SnapshotScan(Table table, Schema schema, TableScanContext context) {
    super(table, schema, context);
  }

  protected Long snapshotId() {
    return context().snapshotId();
  }

  protected abstract CloseableIterable<T> doPlanFiles();

  /**
   * Whether this scan's schema is the table's data schema.
   *
   * <p>False for scans whose schema is derived rather than the table's own, such as metadata table
   * scans and position deletes scans. Those cannot resolve a data schema, so partition specs must
   * not be bound to their schema and {@link BindingSchema#SNAPSHOT} is not available to them.
   */
  protected boolean hasDataSchema() {
    return useSnapshotSchema();
  }

  /**
   * @deprecated since 1.12.0, will be removed in 1.13.0; override {@link #hasDataSchema()} instead.
   *     The name described a behaviour that is now the caller's choice, not the scan's.
   */
  @Deprecated
  protected boolean useSnapshotSchema() {
    return false;
  }

  protected ScanMetrics scanMetrics() {
    if (scanMetrics == null) {
      this.scanMetrics = ScanMetrics.of(new DefaultMetricsContext());
    }

    return scanMetrics;
  }

  protected Map<Integer, PartitionSpec> specs() {
    return specs(table().specs().keySet());
  }

  /**
   * Returns the partition specs with the given IDs, bound to this scan's schema when time
   * travelling.
   *
   * <p>Callers that know which specs a scan can reach should pass only those IDs. A manifest
   * written at or before the selected snapshot can only reference a spec that existed then, so
   * specs created afterwards are never used for planning. Binding them anyway is wasted work and
   * can fail: a spec added after the selected snapshot may name a column that did not exist yet, or
   * may carry a partition field whose name resolves to a different field in the older schema.
   *
   * @param specIds the IDs of the specs this scan can reference
   * @return the requested specs, bound to this scan's schema when time travelling
   */
  protected Map<Integer, PartitionSpec> specs(Set<Integer> specIds) {
    Map<Integer, PartitionSpec> specs = table().specs();

    // scans without a data schema cannot bind data partition specs to it
    if (!hasDataSchema() || snapshotId() == null) {
      return specs;
    }

    Schema scanSchema = tableSchema();

    // table specs are already bound to the table schema, so rebinding them to it is a no-op. This
    // is the common case for BindingSchema.TABLE.
    if (scanSchema.schemaId() == table().schema().schemaId()) {
      return specs;
    }

    ImmutableMap.Builder<Integer, PartitionSpec> newSpecs =
        ImmutableMap.builderWithExpectedSize(specIds.size());
    for (Integer specId : specIds) {
      PartitionSpec spec = specs.get(specId);
      Preconditions.checkArgument(spec != null, "Cannot find partition spec with ID %s", specId);
      newSpecs.put(specId, spec.toUnbound().bind(scanSchema, true));
    }

    return newSpecs.build();
  }

  /** Returns the IDs of the partition specs referenced by the given manifests. */
  protected static Set<Integer> specIdsIn(List<ManifestFile> manifests) {
    Set<Integer> specIds = Sets.newHashSet();
    manifests.forEach(manifest -> specIds.add(manifest.partitionSpecId()));
    return specIds;
  }

  /** Returns the IDs of the partition specs referenced by the given data and delete manifests. */
  protected static Set<Integer> specIdsIn(
      List<ManifestFile> dataManifests, List<ManifestFile> deleteManifests) {
    Set<Integer> specIds = specIdsIn(dataManifests);
    deleteManifests.forEach(manifest -> specIds.add(manifest.partitionSpecId()));
    return specIds;
  }

  /**
   * @deprecated since 1.12.0, will be removed in 2.0.0; use {@link #useSnapshot(long,
   *     BindingSchema)}.
   */
  @Deprecated
  public ThisT useSnapshot(long scanSnapshotId) {
    return useSnapshot(scanSnapshotId, defaultBindingSchema());
  }

  public ThisT useSnapshot(long scanSnapshotId, BindingSchema bindingSchema) {
    Preconditions.checkArgument(bindingSchema != null, "Invalid binding schema: null");
    Preconditions.checkArgument(
        snapshotId() == null, "Cannot override snapshot, already set snapshot id=%s", snapshotId());
    Preconditions.checkArgument(
        table().snapshot(scanSnapshotId) != null,
        "Cannot find snapshot with ID %s",
        scanSnapshotId);
    Preconditions.checkArgument(
        bindingSchema == BindingSchema.TABLE || hasDataSchema(),
        "Cannot use the snapshot schema for %s: it has no data schema",
        getClass().getSimpleName());

    Schema newSchema =
        bindingSchema == BindingSchema.SNAPSHOT
            ? SnapshotUtil.schemaFor(table(), scanSnapshotId)
            : tableSchema();
    TableScanContext newContext = context().useSnapshotId(scanSnapshotId);
    return newRefinedScan(table(), newSchema, newContext);
  }

  /**
   * The binding schema used by the selectors that do not take one.
   *
   * <p>Data scans default to the selected snapshot's schema, which is what a snapshot ID, timestamp
   * or tag read has always been documented to use. Scans without a data schema keep their own.
   */
  private BindingSchema defaultBindingSchema() {
    return hasDataSchema() ? BindingSchema.SNAPSHOT : BindingSchema.TABLE;
  }

  public ThisT useRef(String name) {
    if (SnapshotRef.MAIN_BRANCH.equals(name)) {
      return newRefinedScan(table(), tableSchema(), context());
    }

    Preconditions.checkArgument(
        snapshotId() == null, "Cannot override ref, already set snapshot id=%s", snapshotId());
    Snapshot snapshot = table().snapshot(name);
    Preconditions.checkArgument(snapshot != null, "Cannot find ref %s", name);
    TableScanContext newContext = context().useSnapshotId(snapshot.snapshotId());
    // a branch keeps the table schema and a tag uses the snapshot schema, which is the same
    // distinction BindingSchema makes, expressed by ref instead of by ID
    Schema newSchema = hasDataSchema() ? SnapshotUtil.schemaFor(table(), name) : tableSchema();
    return newRefinedScan(table(), newSchema, newContext);
  }

  /**
   * @deprecated since 1.12.0, will be removed in 2.0.0; use {@link #asOfTime(long, BindingSchema)}.
   */
  @Deprecated
  public ThisT asOfTime(long timestampMillis) {
    return asOfTime(timestampMillis, defaultBindingSchema());
  }

  public ThisT asOfTime(long timestampMillis, BindingSchema bindingSchema) {
    Preconditions.checkArgument(
        snapshotId() == null, "Cannot override snapshot, already set snapshot id=%s", snapshotId());

    return useSnapshot(SnapshotUtil.snapshotIdAsOfTime(table(), timestampMillis), bindingSchema);
  }

  @Override
  public CloseableIterable<T> planFiles() {
    Snapshot snapshot = snapshot();

    if (snapshot == null) {
      LOG.info("Scanning empty table {}", table());
      return CloseableIterable.empty();
    }

    LOG.info(
        "Scanning table {} snapshot {} created at {} with filter {}",
        table(),
        snapshot.snapshotId(),
        DateTimeUtil.formatTimestampMillis(snapshot.timestampMillis()),
        ExpressionUtil.toSanitizedString(filter()));

    Listeners.notifyAll(new ScanEvent(table().name(), snapshot.snapshotId(), filter(), schema()));
    List<Integer> projectedFieldIds = Lists.newArrayList(TypeUtil.getProjectedIds(schema()));
    List<String> projectedFieldNames =
        projectedFieldIds.stream().map(schema()::findColumnName).collect(Collectors.toList());

    Timer.Timed planningDuration = scanMetrics().totalPlanningDuration().start();

    return CloseableIterable.whenComplete(
        doPlanFiles(),
        () -> {
          planningDuration.stop();
          Map<String, String> metadata = Maps.newHashMap(context().options());
          metadata.putAll(EnvironmentContext.get());
          ScanReport scanReport =
              ImmutableScanReport.builder()
                  .schemaId(schema().schemaId())
                  .projectedFieldIds(projectedFieldIds)
                  .projectedFieldNames(projectedFieldNames)
                  .tableName(table().name())
                  .snapshotId(snapshot.snapshotId())
                  .filter(
                      ExpressionUtil.sanitize(
                          schema().asStruct(), filter(), context().caseSensitive()))
                  .scanMetrics(ScanMetricsResult.fromScanMetrics(scanMetrics()))
                  .metadata(metadata)
                  .build();
          context().metricsReporter().report(scanReport);
        });
  }

  public Snapshot snapshot() {
    return snapshotId() != null ? table().snapshot(snapshotId()) : table().currentSnapshot();
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("table", table())
        .add("projection", schema().asStruct())
        .add("filter", filter())
        .add("ignoreResiduals", shouldIgnoreResiduals())
        .add("caseSensitive", isCaseSensitive())
        .toString();
  }
}
