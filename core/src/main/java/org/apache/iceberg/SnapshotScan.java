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
import org.apache.iceberg.types.TypeUtil;
import org.apache.iceberg.util.DateTimeUtil;
import org.apache.iceberg.util.JsonUtil;
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

  /**
   * Controls whether an exact snapshot scan uses the snapshot schema.
   *
   * <p>Accepted values are {@code true} and {@code false}; the default is {@code true}. A false
   * value retains the scan's schema. This option must be set before {@link #useSnapshot(long)} and
   * cannot be combined with a non-main {@link #useRef(String)} or {@link #asOfTime(long)}.
   */
  public static final String USE_SNAPSHOT_SCHEMA = "use-snapshot-schema";

  /**
   * Supplies the schema retained by an exact snapshot scan.
   *
   * <p>The value must be a schema JSON object with a schema ID and can only be used when {@link
   * #USE_SNAPSHOT_SCHEMA} is {@code false}. This option must be set before {@link
   * #useSnapshot(long)} and cannot be combined with a non-main {@link #useRef(String)} or {@link
   * #asOfTime(long)}.
   */
  public static final String SCAN_SCHEMA = "scan-schema";

  private static final boolean USE_SNAPSHOT_SCHEMA_DEFAULT = true;
  private static final Logger LOG = LoggerFactory.getLogger(SnapshotScan.class);

  private ScanMetrics scanMetrics;

  protected SnapshotScan(Table table, Schema schema, TableScanContext context) {
    super(table, schema, context);
  }

  protected Long snapshotId() {
    return context().snapshotId();
  }

  protected abstract CloseableIterable<T> doPlanFiles();

  // controls whether to use the snapshot schema while time travelling
  protected boolean useSnapshotSchema() {
    return false;
  }

  protected boolean shouldUseSnapshotSchema() {
    String value = options().get(USE_SNAPSHOT_SCHEMA);
    boolean configuredValue =
        value != null ? Boolean.parseBoolean(value) : USE_SNAPSHOT_SCHEMA_DEFAULT;
    return useSnapshotSchema() && configuredValue;
  }

  protected ScanMetrics scanMetrics() {
    if (scanMetrics == null) {
      this.scanMetrics = ScanMetrics.of(new DefaultMetricsContext());
    }

    return scanMetrics;
  }

  protected Map<Integer, PartitionSpec> specs() {
    Map<Integer, PartitionSpec> specs = table().specs();
    // the table's specs are already bound to the scan's schema
    if (!useSnapshotSchema()
        || snapshotId() == null
        || tableSchema().sameSchema(table().schema())) {
      return specs;
    }

    // bind specs to the schema retained by this scan
    Schema snapshotSchema = tableSchema();
    ImmutableMap.Builder<Integer, PartitionSpec> newSpecs =
        ImmutableMap.builderWithExpectedSize(specs.size());
    for (Map.Entry<Integer, PartitionSpec> entry : specs.entrySet()) {
      newSpecs.put(entry.getKey(), entry.getValue().toUnbound().bind(snapshotSchema, true));
    }

    return newSpecs.build();
  }

  public ThisT useSnapshot(long scanSnapshotId) {
    Preconditions.checkArgument(
        snapshotId() == null, "Cannot override snapshot, already set snapshot id=%s", snapshotId());
    Preconditions.checkArgument(
        table().snapshot(scanSnapshotId) != null,
        "Cannot find snapshot with ID %s",
        scanSnapshotId);

    Schema configuredScanSchema = configuredScanSchema();
    if (configuredScanSchema != null) {
      Preconditions.checkArgument(
          "false".equalsIgnoreCase(options().get(USE_SNAPSHOT_SCHEMA)),
          "Cannot use scan option %s unless scan option %s is false",
          SCAN_SCHEMA,
          USE_SNAPSHOT_SCHEMA);
    }

    Schema newSchema =
        shouldUseSnapshotSchema()
            ? SnapshotUtil.schemaFor(table(), scanSnapshotId)
            : scanSchema(configuredScanSchema);
    TableScanContext newContext = context().useSnapshotId(scanSnapshotId);
    return newRefinedScan(table(), newSchema, newContext);
  }

  public ThisT useRef(String name) {
    if (SnapshotRef.MAIN_BRANCH.equals(name)) {
      return newRefinedScan(table(), tableSchema(), context());
    }

    String exactSnapshotOption = exactSnapshotOption();
    Preconditions.checkArgument(
        exactSnapshotOption == null,
        "Cannot use non-main ref when scan option %s is set",
        exactSnapshotOption);

    Preconditions.checkArgument(
        snapshotId() == null, "Cannot override ref, already set snapshot id=%s", snapshotId());
    Snapshot snapshot = table().snapshot(name);
    Preconditions.checkArgument(snapshot != null, "Cannot find ref %s", name);
    TableScanContext newContext = context().useSnapshotId(snapshot.snapshotId());
    Schema newSchema = useSnapshotSchema() ? SnapshotUtil.schemaFor(table(), name) : tableSchema();
    return newRefinedScan(table(), newSchema, newContext);
  }

  public ThisT asOfTime(long timestampMillis) {
    String exactSnapshotOption = exactSnapshotOption();
    Preconditions.checkArgument(
        exactSnapshotOption == null,
        "Cannot use timestamp when scan option %s is set",
        exactSnapshotOption);
    Preconditions.checkArgument(
        snapshotId() == null, "Cannot override snapshot, already set snapshot id=%s", snapshotId());

    return useSnapshot(SnapshotUtil.snapshotIdAsOfTime(table(), timestampMillis));
  }

  @Override
  public ThisT option(String property, String value) {
    if (USE_SNAPSHOT_SCHEMA.equals(property) || SCAN_SCHEMA.equals(property)) {
      Preconditions.checkArgument(
          snapshotId() == null,
          "Cannot set scan option %s, snapshot already set to id=%s",
          property,
          snapshotId());
    }

    if (USE_SNAPSHOT_SCHEMA.equals(property)) {
      Preconditions.checkArgument(
          value != null && ("true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value)),
          "Invalid value for scan option %s: %s (must be true or false)",
          USE_SNAPSHOT_SCHEMA,
          value);
    }

    if (SCAN_SCHEMA.equals(property)) {
      Preconditions.checkArgument(
          value != null, "Invalid value for scan option %s: null", property);
    }

    return super.option(property, value);
  }

  private String exactSnapshotOption() {
    if (options().containsKey(USE_SNAPSHOT_SCHEMA)) {
      return USE_SNAPSHOT_SCHEMA;
    } else if (options().containsKey(SCAN_SCHEMA)) {
      return SCAN_SCHEMA;
    }

    return null;
  }

  private Schema configuredScanSchema() {
    String schemaJson = options().get(SCAN_SCHEMA);
    if (schemaJson == null) {
      return null;
    }

    return JsonUtil.parse(
        schemaJson,
        json -> {
          Preconditions.checkArgument(
              json.hasNonNull("schema-id"), "Invalid scan schema: missing schema-id");
          return SchemaParser.fromJson(json);
        });
  }

  private Schema scanSchema(Schema configuredScanSchema) {
    if (configuredScanSchema == null) {
      return tableSchema();
    }

    Schema knownSchema = table().schemas().get(configuredScanSchema.schemaId());
    Preconditions.checkArgument(
        knownSchema != null, "Cannot find scan schema with ID %s", configuredScanSchema.schemaId());
    Preconditions.checkArgument(
        knownSchema.sameSchema(configuredScanSchema),
        "Scan schema with ID %s does not match the table schema with that ID",
        configuredScanSchema.schemaId());
    return knownSchema;
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
          metadata.remove(SCAN_SCHEMA);
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
