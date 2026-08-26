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
package org.apache.iceberg.spark.action;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collections;
import java.util.LongSummaryStatistics;
import java.util.stream.StreamSupport;
import org.apache.iceberg.FileScanTask;
import org.apache.iceberg.Schema;
import org.apache.iceberg.Table;
import org.apache.iceberg.TableProperties;
import org.apache.iceberg.actions.RewriteDataFiles;
import org.apache.iceberg.actions.SizeBasedFileRewritePlanner;
import org.apache.iceberg.io.CloseableIterable;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.spark.Spark3Util;
import org.apache.iceberg.spark.SparkSchemaUtil;
import org.apache.iceberg.spark.SparkSessionCatalog;
import org.apache.iceberg.spark.actions.SparkActions;
import org.apache.iceberg.types.Types;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.connector.catalog.Identifier;
import org.apache.spark.sql.connector.expressions.Transform;
import org.apache.spark.sql.internal.SQLConf;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Measures a Spark rewrite with concurrent file groups and partial-progress commits.
 *
 * <p>To run this benchmark for Spark 4.1: <code>
 *   ./gradlew :iceberg-spark:iceberg-spark-4.1_2.13:jmh
 *       -PjmhIncludeRegex=RewriteDataFilesPartialProgressBenchmark.rewriteDataFiles
 *       -PjmhOutputPath=benchmark/rewrite-partial-progress-results.txt
 *       -PjmhJsonOutputPath=benchmark/rewrite-partial-progress-results.json
 * </code>
 */
@Warmup(iterations = 3)
@Measurement(iterations = 10)
@Fork(value = 1, jvmArgsAppend = "--add-opens=java.base/java.nio=ALL-UNNAMED")
public class RewriteDataFilesPartialProgressBenchmark extends IcebergCompactionBenchmark {

  private static final String[] NAMESPACE = new String[] {"default"};
  private static final String NAME = "partialprogressbench";
  private static final Identifier IDENT = Identifier.of(NAMESPACE, NAME);
  private static final int INPUT_FILES = 20;
  private static final int FILE_GROUPS = 10;
  private static final long TOTAL_ROWS = 100_000L;
  private static final long EXPECTED_ID_SUM = TOTAL_ROWS * (TOTAL_ROWS - 1) / 2;

  @Param({"1", "4"})
  private int concurrentRewrites;

  private long maxFileGroupSize;
  private RewriteDataFiles.Result result;

  @Override
  protected String tableName() {
    return NAME;
  }

  @Benchmark
  @Threads(1)
  public RewriteDataFiles.Result rewriteDataFiles() {
    this.result =
        SparkActions.get()
            .rewriteDataFiles(table())
            .option(SizeBasedFileRewritePlanner.REWRITE_ALL, "true")
            .option(RewriteDataFiles.MAX_FILE_GROUP_SIZE_BYTES, Long.toString(maxFileGroupSize))
            .option(
                RewriteDataFiles.MAX_CONCURRENT_FILE_GROUP_REWRITES,
                Integer.toString(concurrentRewrites))
            .option(RewriteDataFiles.PARTIAL_PROGRESS_ENABLED, "true")
            .option(RewriteDataFiles.PARTIAL_PROGRESS_MAX_COMMITS, Integer.toString(FILE_GROUPS))
            .option(RewriteDataFiles.PARTIAL_PROGRESS_MAX_FAILED_COMMITS, "0")
            .execute();
    return this.result;
  }

  @TearDown(Level.Invocation)
  public void verifyRewrite() throws IOException {
    Preconditions.checkState(
        result.rewriteResults().size() == FILE_GROUPS,
        "Expected %s rewritten groups, found %s",
        FILE_GROUPS,
        result.rewriteResults().size());
    Preconditions.checkState(
        result.rewriteFailures().isEmpty(),
        "Expected all rewrites to succeed, found %s failures",
        result.rewriteFailures().size());
    Preconditions.checkState(
        result.rewrittenDataFilesCount() == INPUT_FILES,
        "Expected %s rewritten files, found %s",
        INPUT_FILES,
        result.rewrittenDataFilesCount());
    Preconditions.checkState(
        result.addedDataFilesCount() == FILE_GROUPS,
        "Expected %s added files, found %s",
        FILE_GROUPS,
        result.addedDataFilesCount());

    Table rewrittenTable = table();
    long snapshotCount =
        StreamSupport.stream(rewrittenTable.snapshots().spliterator(), false).count();
    Preconditions.checkState(
        snapshotCount == FILE_GROUPS + 1,
        "Expected %s snapshots, found %s",
        FILE_GROUPS + 1,
        snapshotCount);

    Dataset<Row> rewrittenData = spark().table(tableName());
    Preconditions.checkState(
        rewrittenData.count() == TOTAL_ROWS, "Expected %s rows after rewrite", TOTAL_ROWS);
    long actualIDSum = rewrittenData.selectExpr("sum(id)").first().getLong(0);
    Preconditions.checkState(
        actualIDSum == EXPECTED_ID_SUM,
        "Expected ID sum %s, found %s",
        EXPECTED_ID_SUM,
        actualIDSum);
  }

  @Override
  protected void initTable() {
    Schema schema = new Schema(Types.NestedField.required(1, "id", Types.LongType.get()));

    try {
      SparkSessionCatalog<?> catalog =
          (SparkSessionCatalog<?>)
              Spark3Util.catalogAndIdentifier(spark(), "spark_catalog").catalog();
      catalog.dropTable(IDENT);
      catalog.createTable(
          IDENT, SparkSchemaUtil.convert(schema), new Transform[0], Collections.emptyMap());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    table()
        .updateProperties()
        .set(TableProperties.COMMIT_NUM_RETRIES, Integer.toString(FILE_GROUPS * 2))
        .commit();
  }

  @Override
  protected void appendData() {
    writeData(spark().range(0, TOTAL_ROWS).toDF().repartition(INPUT_FILES));

    Table inputTable = table();
    LongSummaryStatistics inputFiles;
    try (CloseableIterable<FileScanTask> tasks = inputTable.newScan().planFiles()) {
      inputFiles =
          StreamSupport.stream(tasks.spliterator(), false)
              .mapToLong(FileScanTask::length)
              .summaryStatistics();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }

    Preconditions.checkState(
        inputFiles.getCount() == INPUT_FILES,
        "Expected %s input files, found %s",
        INPUT_FILES,
        inputFiles.getCount());
    Preconditions.checkState(
        inputFiles.getMin() * 3 > inputFiles.getMax() * 2,
        "Input file sizes vary too much to form two-file groups: min=%s, max=%s",
        inputFiles.getMin(),
        inputFiles.getMax());
    this.maxFileGroupSize = inputFiles.getMax() * 2;
  }

  @Override
  protected void setupSpark() {
    super.setupSpark();
    spark().conf().set(SQLConf.ADAPTIVE_EXECUTION_ENABLED().key(), "false");
  }
}
