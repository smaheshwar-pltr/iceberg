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

import java.io.IOException;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.apache.iceberg.data.Record;
import org.apache.iceberg.deletes.PositionDelete;
import org.apache.iceberg.deletes.PositionDeleteWriter;
import org.apache.iceberg.encryption.EncryptedFiles;
import org.apache.iceberg.encryption.EncryptedKey;
import org.apache.iceberg.encryption.EncryptedOutputFile;
import org.apache.iceberg.encryption.EncryptingFileIO;
import org.apache.iceberg.encryption.EncryptionKeyMetadata;
import org.apache.iceberg.encryption.EncryptionManager;
import org.apache.iceberg.encryption.NativeEncryptionKeyMetadata;
import org.apache.iceberg.encryption.NativeEncryptionOutputFile;
import org.apache.iceberg.encryption.PlaintextEncryptionManager;
import org.apache.iceberg.exceptions.RuntimeIOException;
import org.apache.iceberg.io.CloseableIterable;
import org.apache.iceberg.io.CloseableIterator;
import org.apache.iceberg.io.FileIO;
import org.apache.iceberg.io.InputFile;
import org.apache.iceberg.io.OutputFile;
import org.apache.iceberg.puffin.Blob;
import org.apache.iceberg.puffin.BlobMetadata;
import org.apache.iceberg.puffin.Puffin;
import org.apache.iceberg.puffin.PuffinCompressionCodec;
import org.apache.iceberg.puffin.PuffinReader;
import org.apache.iceberg.puffin.PuffinWriter;
import org.apache.iceberg.relocated.com.google.common.base.Preconditions;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableList;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableMap;
import org.apache.iceberg.relocated.com.google.common.collect.Lists;
import org.apache.iceberg.relocated.com.google.common.collect.Maps;
import org.apache.iceberg.relocated.com.google.common.collect.Sets;
import org.apache.iceberg.util.ByteBuffers;
import org.apache.iceberg.util.ContentFileUtil;
import org.apache.iceberg.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Utilities for Rewrite table path action. */
public class RewriteTablePathUtil {

  private static final Logger LOG = LoggerFactory.getLogger(RewriteTablePathUtil.class);
  // Use the POSIX separator instead of File.separator because File.separator is dependent on
  // the client environment and not the target filesystem. POSIX is compatible with S3, GCS, etc
  public static final String FILE_SEPARATOR = "/";

  private RewriteTablePathUtil() {}

  /**
   * Rewrite result.
   *
   * @param <T> type of file to rewrite
   */
  public static class RewriteResult<T> implements Serializable {
    private final Set<T> toRewrite = Sets.newHashSet();
    private final Set<Pair<String, String>> copyPlan = Sets.newHashSet();
    private final Map<String, Long> rewrittenManifestLengths = Maps.newHashMap();
    private final Map<String, byte[]> rewrittenManifestKeyMetadata = Maps.newHashMap();
    private final Map<String, String> rewrittenManifestStagingPaths = Maps.newHashMap();
    private final Map<Long, String> rewrittenManifestListKeyIDs = Maps.newHashMap();

    public RewriteResult() {}

    public RewriteResult<T> append(RewriteResult<T> r1) {
      toRewrite.addAll(r1.toRewrite);
      copyPlan.addAll(r1.copyPlan);
      rewrittenManifestLengths.putAll(r1.rewrittenManifestLengths);
      rewrittenManifestKeyMetadata.putAll(r1.rewrittenManifestKeyMetadata);
      rewrittenManifestStagingPaths.putAll(r1.rewrittenManifestStagingPaths);
      rewrittenManifestListKeyIDs.putAll(r1.rewrittenManifestListKeyIDs);
      return this;
    }

    /** Returns next list of files to rewrite (discovered by rewriting this file) */
    public Set<T> toRewrite() {
      return toRewrite;
    }

    /**
     * Returns a copy plan of files whose metadata were rewritten, for each file a source and target
     * location
     */
    public Set<Pair<String, String>> copyPlan() {
      return copyPlan;
    }

    /** Records the byte length of the manifest rewritten from the given source manifest path */
    public void addRewrittenManifestLength(String sourceManifestPath, long length) {
      rewrittenManifestLengths.put(sourceManifestPath, length);
    }

    /** Returns the byte length of each rewritten manifest, keyed by source manifest path */
    public Map<String, Long> rewrittenManifestLengths() {
      return Collections.unmodifiableMap(rewrittenManifestLengths);
    }

    /** Records key metadata for the manifest rewritten from the given source manifest path. */
    protected void addRewrittenManifestKeyMetadata(
        String sourceManifestPath, ByteBuffer keyMetadata) {
      rewrittenManifestKeyMetadata.put(
          sourceManifestPath, ByteBuffers.toByteArray(ByteBuffers.copy(keyMetadata)));
    }

    /** Returns key metadata for the manifest rewritten from the given source manifest path. */
    public ByteBuffer rewrittenManifestKeyMetadata(String sourceManifestPath) {
      byte[] keyMetadata = rewrittenManifestKeyMetadata.get(sourceManifestPath);
      return keyMetadata != null ? ByteBuffer.wrap(keyMetadata).asReadOnlyBuffer() : null;
    }

    /** Records the staging path for the manifest rewritten from the given source manifest path. */
    protected void addRewrittenManifestStagingPath(String sourceManifestPath, String stagingPath) {
      rewrittenManifestStagingPaths.put(sourceManifestPath, stagingPath);
    }

    /** Returns the staging path for the manifest rewritten from the given source manifest path. */
    public String rewrittenManifestStagingPath(String sourceManifestPath) {
      return rewrittenManifestStagingPaths.get(sourceManifestPath);
    }

    /** Records the key ID for a rewritten snapshot's manifest list. */
    private void addRewrittenManifestListKeyID(long snapshotID, String keyID) {
      if (keyID != null) {
        rewrittenManifestListKeyIDs.put(snapshotID, keyID);
      }
    }

    /** Returns rewritten manifest list key IDs, keyed by snapshot ID. */
    public Map<Long, String> rewrittenManifestListKeyIDs() {
      return Collections.unmodifiableMap(rewrittenManifestListKeyIDs);
    }
  }

  /** Result of rewriting a single file. */
  public static class RewriteFileResult implements Serializable {
    private final long fileSizeInBytes;
    private final byte[] keyMetadata;
    private final String stagingPath;

    private RewriteFileResult(long fileSizeInBytes, ByteBuffer keyMetadata) {
      this(fileSizeInBytes, keyMetadata, null);
    }

    private RewriteFileResult(long fileSizeInBytes, ByteBuffer keyMetadata, String stagingPath) {
      this.fileSizeInBytes = fileSizeInBytes;
      this.keyMetadata = ByteBuffers.toByteArray(ByteBuffers.copy(keyMetadata));
      this.stagingPath = stagingPath;
    }

    public long fileSizeInBytes() {
      return fileSizeInBytes;
    }

    public ByteBuffer keyMetadata() {
      return keyMetadata != null ? ByteBuffer.wrap(keyMetadata).asReadOnlyBuffer() : null;
    }

    private String stagingPath() {
      return stagingPath;
    }
  }

  /**
   * Create a new table metadata object, replacing path references
   *
   * @param metadata source table metadata
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @return copy of table metadata with paths replaced
   */
  public static TableMetadata replacePaths(
      TableMetadata metadata, String sourcePrefix, String targetPrefix) {
    return replacePaths(
        metadata, sourcePrefix, targetPrefix, Collections.emptyMap(), metadata.encryptionKeys());
  }

  /**
   * Create a new table metadata object, replacing path and encryption references.
   *
   * @param metadata source table metadata
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @param snapshotKeyIDs replacement manifest list key IDs, keyed by snapshot ID
   * @param encryptionKeys encryption keys to store in the rewritten metadata
   * @return copy of table metadata with paths and encryption references replaced
   */
  public static TableMetadata replacePaths(
      TableMetadata metadata,
      String sourcePrefix,
      String targetPrefix,
      Map<Long, String> snapshotKeyIDs,
      List<EncryptedKey> encryptionKeys) {
    String newLocation = newPath(metadata.location(), sourcePrefix, targetPrefix);
    List<Snapshot> newSnapshots =
        updatePathInSnapshots(metadata, sourcePrefix, targetPrefix, snapshotKeyIDs);
    List<TableMetadata.MetadataLogEntry> metadataLogEntries =
        updatePathInMetadataLogs(metadata, sourcePrefix, targetPrefix);
    long snapshotId =
        metadata.currentSnapshot() == null ? -1 : metadata.currentSnapshot().snapshotId();
    Map<String, String> properties =
        updateProperties(metadata.properties(), sourcePrefix, targetPrefix);

    return new TableMetadata(
        null,
        metadata.formatVersion(),
        metadata.uuid(),
        newLocation,
        metadata.lastSequenceNumber(),
        metadata.lastUpdatedMillis(),
        metadata.lastColumnId(),
        metadata.currentSchemaId(),
        metadata.schemas(),
        metadata.defaultSpecId(),
        metadata.specs(),
        metadata.lastAssignedPartitionId(),
        metadata.defaultSortOrderId(),
        metadata.sortOrders(),
        properties,
        snapshotId,
        newSnapshots,
        null,
        metadata.snapshotLog(),
        metadataLogEntries,
        metadata.refs(),
        updatePathInStatisticsFiles(metadata.statisticsFiles(), sourcePrefix, targetPrefix),
        updatePathInPartitionStatisticsFiles(
            metadata.partitionStatisticsFiles(), sourcePrefix, targetPrefix),
        metadata.nextRowId(),
        ImmutableList.copyOf(encryptionKeys),
        metadata.changes());
  }

  private static Map<String, String> updateProperties(
      Map<String, String> tableProperties, String sourcePrefix, String targetPrefix) {
    Map<String, String> properties = Maps.newHashMap(tableProperties);
    updatePathInProperty(properties, sourcePrefix, targetPrefix, TableProperties.OBJECT_STORE_PATH);
    updatePathInProperty(
        properties, sourcePrefix, targetPrefix, TableProperties.WRITE_FOLDER_STORAGE_LOCATION);
    updatePathInProperty(
        properties, sourcePrefix, targetPrefix, TableProperties.WRITE_DATA_LOCATION);
    updatePathInProperty(
        properties, sourcePrefix, targetPrefix, TableProperties.WRITE_METADATA_LOCATION);

    return properties;
  }

  private static void updatePathInProperty(
      Map<String, String> properties,
      String sourcePrefix,
      String targetPrefix,
      String propertyName) {
    if (properties.containsKey(propertyName)) {
      properties.put(
          propertyName, newPath(properties.get(propertyName), sourcePrefix, targetPrefix));
    }
  }

  private static List<StatisticsFile> updatePathInStatisticsFiles(
      List<StatisticsFile> statisticsFiles, String sourcePrefix, String targetPrefix) {
    return statisticsFiles.stream()
        .map(
            existing ->
                new GenericStatisticsFile(
                    existing.snapshotId(),
                    newPath(existing.path(), sourcePrefix, targetPrefix),
                    existing.fileSizeInBytes(),
                    existing.fileFooterSizeInBytes(),
                    existing.blobMetadata()))
        .collect(Collectors.toList());
  }

  /**
   * This method updates the file paths in a list of PartitionStatisticsFile. It replaces the
   * sourcePrefix in the file paths with the targetPrefix.
   *
   * @param partitionStatisticsFiles The list of PartitionStatisticsFile to update.
   * @param sourcePrefix The prefix to be replaced in the file paths.
   * @param targetPrefix The new prefix to replace the sourcePrefix in the file paths.
   * @return A new list of PartitionStatisticsFile with updated file paths.
   */
  private static List<PartitionStatisticsFile> updatePathInPartitionStatisticsFiles(
      List<PartitionStatisticsFile> partitionStatisticsFiles,
      String sourcePrefix,
      String targetPrefix) {

    return partitionStatisticsFiles.stream()
        .map(
            existing ->
                ImmutableGenericPartitionStatisticsFile.builder()
                    .snapshotId(existing.snapshotId())
                    .path(newPath(existing.path(), sourcePrefix, targetPrefix))
                    .fileSizeInBytes(existing.fileSizeInBytes())
                    .build())
        .collect(Collectors.toList());
  }

  private static List<TableMetadata.MetadataLogEntry> updatePathInMetadataLogs(
      TableMetadata metadata, String sourcePrefix, String targetPrefix) {
    List<TableMetadata.MetadataLogEntry> metadataLogEntries =
        Lists.newArrayListWithCapacity(metadata.previousFiles().size());
    for (TableMetadata.MetadataLogEntry metadataLog : metadata.previousFiles()) {
      TableMetadata.MetadataLogEntry newMetadataLog =
          new TableMetadata.MetadataLogEntry(
              metadataLog.timestampMillis(),
              newPath(metadataLog.file(), sourcePrefix, targetPrefix));
      metadataLogEntries.add(newMetadataLog);
    }
    return metadataLogEntries;
  }

  private static List<Snapshot> updatePathInSnapshots(
      TableMetadata metadata,
      String sourcePrefix,
      String targetPrefix,
      Map<Long, String> snapshotKeyIDs) {
    List<Snapshot> newSnapshots = Lists.newArrayListWithCapacity(metadata.snapshots().size());
    for (Snapshot snapshot : metadata.snapshots()) {
      String newManifestListLocation =
          newPath(snapshot.manifestListLocation(), sourcePrefix, targetPrefix);
      Snapshot newSnapshot =
          new BaseSnapshot(
              snapshot.sequenceNumber(),
              snapshot.snapshotId(),
              snapshot.parentId(),
              snapshot.timestampMillis(),
              snapshot.operation(),
              snapshot.summary(),
              snapshot.schemaId(),
              newManifestListLocation,
              snapshot.firstRowId(),
              snapshot.addedRows(),
              snapshotKeyIDs.containsKey(snapshot.snapshotId())
                  ? snapshotKeyIDs.get(snapshot.snapshotId())
                  : snapshot.keyId());
      newSnapshots.add(newSnapshot);
    }
    return newSnapshots;
  }

  /**
   * Rewrite a manifest list representing a snapshot, replacing path references.
   *
   * @param snapshot snapshot represented by the manifest list
   * @param io file io
   * @param tableMetadata metadata of table
   * @param rewrittenManifestLengths byte length of each manifest rewritten by this run, keyed by
   *     source manifest path. Only these manifests are rewritten; any other manifest in the
   *     snapshot keeps the length recorded in the source table.
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @param stagingDir staging directory
   * @param outputPath location to write the manifest list
   * @return a copy plan for manifest files whose metadata were contained in the rewritten manifest
   *     list
   */
  public static RewriteResult<ManifestFile> rewriteManifestList(
      Snapshot snapshot,
      FileIO io,
      TableMetadata tableMetadata,
      Map<String, Long> rewrittenManifestLengths,
      String sourcePrefix,
      String targetPrefix,
      String stagingDir,
      String outputPath) {
    RewriteResult<ContentFile<?>> rewrittenManifests = new RewriteResult<>();
    rewrittenManifestLengths.forEach(rewrittenManifests::addRewrittenManifestLength);
    return rewriteManifestList(
        snapshot,
        io,
        tableMetadata,
        rewrittenManifests,
        sourcePrefix,
        targetPrefix,
        stagingDir,
        outputPath);
  }

  /**
   * Rewrite a manifest list representing a snapshot, replacing path and encryption references.
   *
   * @param snapshot snapshot represented by the manifest list
   * @param io file io
   * @param tableMetadata metadata of table
   * @param rewrittenManifests metadata for manifests rewritten by this run
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @param stagingDir staging directory
   * @param outputPath location to write the manifest list
   * @return a copy plan and encryption metadata for files represented by the manifest list
   */
  public static RewriteResult<ManifestFile> rewriteManifestList(
      Snapshot snapshot,
      FileIO io,
      TableMetadata tableMetadata,
      RewriteResult<?> rewrittenManifests,
      String sourcePrefix,
      String targetPrefix,
      String stagingDir,
      String outputPath) {
    return rewriteManifestList(
        snapshot,
        io,
        tableMetadata,
        rewrittenManifests,
        Collections.emptyMap(),
        sourcePrefix,
        targetPrefix,
        stagingDir,
        outputPath);
  }

  /**
   * Rewrite a manifest list, using existing target metadata for manifests carried over by an
   * incremental rewrite.
   *
   * @param snapshot snapshot represented by the manifest list
   * @param io file io
   * @param tableMetadata metadata of table
   * @param rewrittenManifests metadata for manifests rewritten by this run
   * @param existingTargetManifests target metadata keyed by source manifest path
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @param stagingDir staging directory
   * @param outputPath location to write the manifest list
   * @return a copy plan and encryption metadata for files represented by the manifest list
   */
  public static RewriteResult<ManifestFile> rewriteManifestList(
      Snapshot snapshot,
      FileIO io,
      TableMetadata tableMetadata,
      RewriteResult<?> rewrittenManifests,
      Map<String, ManifestFile> existingTargetManifests,
      String sourcePrefix,
      String targetPrefix,
      String stagingDir,
      String outputPath) {
    RewriteResult<ManifestFile> result = new RewriteResult<>();
    OutputFile outputFile = io.newOutputFile(outputPath);

    List<ManifestFile> manifestFiles = manifestFilesInSnapshot(io, snapshot);
    manifestFiles.forEach(
        mf ->
            Preconditions.checkArgument(
                mf.path().startsWith(sourcePrefix),
                "Encountered manifest file %s not under the source prefix %s",
                mf.path(),
                sourcePrefix));

    long carriedOver =
        manifestFiles.stream()
            .filter(mf -> !rewrittenManifests.rewrittenManifestLengths.containsKey(mf.path()))
            .count();
    if (carriedOver > 0) {
      LOG.info(
          "{} of {} manifests in {} were not rewritten in this run and keep their source length",
          carriedOver,
          manifestFiles.size(),
          snapshot.manifestListLocation());
    }

    EncryptionManager encryptionManager =
        (io instanceof EncryptingFileIO)
            ? ((EncryptingFileIO) io).encryptionManager()
            : PlaintextEncryptionManager.instance();

    ManifestListWriter writer =
        ManifestLists.write(
            tableMetadata.formatVersion(),
            outputFile,
            encryptionManager,
            snapshot.snapshotId(),
            snapshot.parentId(),
            snapshot.sequenceNumber(),
            snapshot.firstRowId());

    try (writer) {

      for (ManifestFile file : manifestFiles) {
        ManifestFile newFile = file.copy();
        ((StructLike) newFile).set(0, newPath(newFile.path(), sourcePrefix, targetPrefix));
        if (rewrittenManifests.rewrittenManifestLengths.containsKey(file.path())) {
          ((StructLike) newFile)
              .set(1, rewrittenManifests.rewrittenManifestLengths.get(file.path()));
          setManifestKeyMetadata(
              newFile, rewrittenManifests.rewrittenManifestKeyMetadata(file.path()));
        } else {
          ManifestFile existingTargetManifest = existingTargetManifests.get(file.path());
          if (existingTargetManifest != null) {
            ((StructLike) newFile).set(1, existingTargetManifest.length());
            setManifestKeyMetadata(newFile, existingTargetManifest.keyMetadata());
          }
        }

        writer.add(newFile);

        if (rewrittenManifests.rewrittenManifestLengths.containsKey(file.path())) {
          result.toRewrite().add(file);
          String rewrittenStagingPath =
              rewrittenManifests.rewrittenManifestStagingPath(file.path());
          result
              .copyPlan()
              .add(
                  Pair.of(
                      rewrittenStagingPath != null
                          ? rewrittenStagingPath
                          : stagingPath(file.path(), sourcePrefix, stagingDir),
                      newFile.path()));
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException(
          "Failed to rewrite the manifest list file " + snapshot.manifestListLocation(), e);
    }

    ManifestListFile rewrittenManifestList;
    synchronized (encryptionManager) {
      rewrittenManifestList = writer.toManifestListFile();
    }
    result.addRewrittenManifestListKeyID(
        snapshot.snapshotId(), rewrittenManifestList.encryptionKeyID());
    return result;
  }

  private static void setManifestKeyMetadata(ManifestFile manifest, ByteBuffer keyMetadata) {
    ((StructLike) manifest).set(14, keyMetadata);
  }

  private static List<ManifestFile> manifestFilesInSnapshot(FileIO io, Snapshot snapshot) {
    try {
      return snapshot.allManifests(io);
    } catch (RuntimeIOException e) {
      LOG.warn("Failed to read manifest list {}", snapshot.manifestListLocation(), e);
      return ImmutableList.of();
    }
  }

  /**
   * Rewrite a data manifest, replacing path references.
   *
   * @param manifestFile source manifest file to rewrite
   * @param snapshotIds snapshot ids for filtering returned data manifest entries
   * @param outputFile output file to rewrite manifest file to
   * @param io file io
   * @param format format of the manifest file
   * @param specsById map of partition specs by id
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @return a copy plan of content files in the manifest that was rewritten, recording the
   *     rewritten manifest's byte length
   */
  public static RewriteResult<DataFile> rewriteDataManifest(
      ManifestFile manifestFile,
      Set<Long> snapshotIds,
      OutputFile outputFile,
      FileIO io,
      int format,
      Map<Integer, PartitionSpec> specsById,
      String sourcePrefix,
      String targetPrefix)
      throws IOException {
    return rewriteDataManifest(
        manifestFile,
        snapshotIds,
        EncryptedFiles.plainAsEncryptedOutput(outputFile),
        io,
        format,
        specsById,
        sourcePrefix,
        targetPrefix);
  }

  /**
   * Rewrite a data manifest, replacing path references and retaining output encryption metadata.
   *
   * @param manifestFile source manifest file to rewrite
   * @param snapshotIds snapshot ids for filtering returned data manifest entries
   * @param outputFile encrypted output file to rewrite manifest file to
   * @param io file io
   * @param format format of the manifest file
   * @param specsById map of partition specs by id
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @return a copy plan and metadata for the rewritten manifest
   */
  public static RewriteResult<DataFile> rewriteDataManifest(
      ManifestFile manifestFile,
      Set<Long> snapshotIds,
      EncryptedOutputFile outputFile,
      FileIO io,
      int format,
      Map<Integer, PartitionSpec> specsById,
      String sourcePrefix,
      String targetPrefix)
      throws IOException {
    PartitionSpec spec = specsById.get(manifestFile.partitionSpecId());
    ManifestWriter<DataFile> writer =
        ManifestFiles.write(format, spec, outputFile, manifestFile.snapshotId());
    RewriteResult<DataFile> result;
    try (writer;
        ManifestReader<DataFile> reader =
            ManifestFiles.read(manifestFile, io, specsById).select(Arrays.asList("*"))) {
      result =
          StreamSupport.stream(reader.entries().spliterator(), false)
              .map(
                  entry ->
                      writeDataFileEntry(
                          entry, snapshotIds, spec, sourcePrefix, targetPrefix, writer))
              .reduce(new RewriteResult<>(), RewriteResult::append);
    }

    ManifestFile rewrittenManifest = writer.toManifestFile();
    result.addRewrittenManifestLength(manifestFile.path(), rewrittenManifest.length());
    result.addRewrittenManifestKeyMetadata(manifestFile.path(), rewrittenManifest.keyMetadata());
    result.addRewrittenManifestStagingPath(manifestFile.path(), rewrittenManifest.path());
    return result;
  }

  /**
   * Rewrite a delete manifest, replacing path references.
   *
   * @param manifestFile source delete manifest to rewrite
   * @param snapshotIds snapshot ids for filtering returned delete manifest entries
   * @param outputFile output file to rewrite manifest file to
   * @param io file io
   * @param format format of the manifest file
   * @param specsById map of partition specs by id
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @param stagingLocation staging location for rewritten files (referred delete file will be
   *     rewritten here)
   * @return a copy plan of content files in the manifest that was rewritten
   * @deprecated since 1.12.0, will be removed in 1.13.0; use the overload that accepts the map of
   *     rewritten position delete file sizes. This overload records the original {@code
   *     file_size_in_bytes}, which can be inconsistent with the rewritten file size on disk once
   *     embedded data file paths change length.
   */
  @Deprecated
  public static RewriteResult<DeleteFile> rewriteDeleteManifest(
      ManifestFile manifestFile,
      Set<Long> snapshotIds,
      OutputFile outputFile,
      FileIO io,
      int format,
      Map<Integer, PartitionSpec> specsById,
      String sourcePrefix,
      String targetPrefix,
      String stagingLocation)
      throws IOException {
    return rewriteDeleteManifest(
        manifestFile,
        snapshotIds,
        outputFile,
        io,
        format,
        specsById,
        sourcePrefix,
        targetPrefix,
        stagingLocation,
        ImmutableMap.of());
  }

  /**
   * Rewrite a delete manifest, replacing path references.
   *
   * <p>This is a metadata-only operation: position delete file content is rewritten separately (see
   * {@link #rewritePositionDelete}). The actual sizes of those rewritten files are supplied via
   * {@code rewrittenDeleteFileSizes} and recorded in the manifest so that {@code
   * file_size_in_bytes} stays consistent with the rewritten file on disk.
   *
   * @param manifestFile source delete manifest to rewrite
   * @param snapshotIds snapshot ids for filtering returned delete manifest entries
   * @param outputFile output file to rewrite manifest file to
   * @param io file io
   * @param format format of the manifest file
   * @param specsById map of partition specs by id
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @param stagingLocation staging location for rewritten position delete files
   * @param rewrittenDeleteFileSizes map from source position delete file path to the actual size of
   *     the rewritten file; entries absent from the map keep their original size
   * @return a copy plan of content files in the manifest that was rewritten, recording the
   *     rewritten manifest's byte length
   */
  public static RewriteResult<DeleteFile> rewriteDeleteManifest(
      ManifestFile manifestFile,
      Set<Long> snapshotIds,
      OutputFile outputFile,
      FileIO io,
      int format,
      Map<Integer, PartitionSpec> specsById,
      String sourcePrefix,
      String targetPrefix,
      String stagingLocation,
      Map<String, Long> rewrittenDeleteFileSizes)
      throws IOException {
    Map<String, RewriteFileResult> rewrittenDeleteFiles = Maps.newHashMap();
    rewrittenDeleteFileSizes.forEach(
        (path, length) -> rewrittenDeleteFiles.put(path, new RewriteFileResult(length, null)));
    return rewriteDeleteManifest(
        manifestFile,
        snapshotIds,
        EncryptedFiles.plainAsEncryptedOutput(outputFile),
        io,
        format,
        specsById,
        sourcePrefix,
        targetPrefix,
        stagingLocation,
        rewrittenDeleteFiles);
  }

  /**
   * Rewrite a delete manifest, replacing path and encryption references.
   *
   * @param manifestFile source delete manifest to rewrite
   * @param snapshotIds snapshot ids for filtering returned delete manifest entries
   * @param outputFile encrypted output file to rewrite manifest file to
   * @param io file io
   * @param format format of the manifest file
   * @param specsById map of partition specs by id
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @param stagingLocation staging location for rewritten position delete files
   * @param rewrittenDeleteFiles metadata for rewritten position delete files, keyed by source path
   * @return a copy plan and metadata for the rewritten manifest
   */
  public static RewriteResult<DeleteFile> rewriteDeleteManifest(
      ManifestFile manifestFile,
      Set<Long> snapshotIds,
      EncryptedOutputFile outputFile,
      FileIO io,
      int format,
      Map<Integer, PartitionSpec> specsById,
      String sourcePrefix,
      String targetPrefix,
      String stagingLocation,
      Map<String, RewriteFileResult> rewrittenDeleteFiles)
      throws IOException {
    PartitionSpec spec = specsById.get(manifestFile.partitionSpecId());
    ManifestWriter<DeleteFile> writer =
        ManifestFiles.writeDeleteManifest(format, spec, outputFile, manifestFile.snapshotId());
    RewriteResult<DeleteFile> result;
    try (writer;
        ManifestReader<DeleteFile> reader =
            ManifestFiles.readDeleteManifest(manifestFile, io, specsById)
                .select(Arrays.asList("*"))) {
      result =
          StreamSupport.stream(reader.entries().spliterator(), false)
              .map(
                  entry ->
                      writeDeleteFileEntry(
                          entry,
                          snapshotIds,
                          spec,
                          sourcePrefix,
                          targetPrefix,
                          stagingLocation,
                          writer,
                          rewrittenDeleteFiles))
              .reduce(new RewriteResult<>(), RewriteResult::append);
    }

    ManifestFile rewrittenManifest = writer.toManifestFile();
    result.addRewrittenManifestLength(manifestFile.path(), rewrittenManifest.length());
    result.addRewrittenManifestKeyMetadata(manifestFile.path(), rewrittenManifest.keyMetadata());
    result.addRewrittenManifestStagingPath(manifestFile.path(), rewrittenManifest.path());
    return result;
  }

  private static RewriteResult<DataFile> writeDataFileEntry(
      ManifestEntry<DataFile> entry,
      Set<Long> snapshotIds,
      PartitionSpec spec,
      String sourcePrefix,
      String targetPrefix,
      ManifestWriter<DataFile> writer) {
    RewriteResult<DataFile> result = new RewriteResult<>();
    DataFile dataFile = entry.file();
    String sourceDataFilePath = dataFile.location();
    Preconditions.checkArgument(
        sourceDataFilePath.startsWith(sourcePrefix),
        "Encountered data file %s not under the source prefix %s",
        sourceDataFilePath,
        sourcePrefix);
    String targetDataFilePath = newPath(sourceDataFilePath, sourcePrefix, targetPrefix);
    DataFile newDataFile =
        DataFiles.builder(spec).copy(entry.file()).withPath(targetDataFilePath).build();
    appendEntryWithFile(entry, writer, newDataFile);
    // keep the following entries in metadata but exclude them from copyPlan
    // 1) deleted data files
    // 2) entries not changed by snapshotIds
    if (entry.isLive() && snapshotIds.contains(entry.snapshotId())) {
      result.copyPlan().add(Pair.of(sourceDataFilePath, newDataFile.location()));
    }
    return result;
  }

  private static RewriteResult<DeleteFile> writeDeleteFileEntry(
      ManifestEntry<DeleteFile> entry,
      Set<Long> snapshotIds,
      PartitionSpec spec,
      String sourcePrefix,
      String targetPrefix,
      String stagingLocation,
      ManifestWriter<DeleteFile> writer,
      Map<String, RewriteFileResult> rewrittenDeleteFiles) {

    DeleteFile file = entry.file();
    RewriteResult<DeleteFile> result = new RewriteResult<>();

    switch (file.content()) {
      case POSITION_DELETES:
        // Path rewrites change the file size; use the measured size, falling back to the original
        // for entries that were not rewritten (e.g. deleted entries not copied to the target).
        RewriteFileResult rewrittenDeleteFile = rewrittenDeleteFiles.get(file.location());
        DeleteFile posDeleteFile =
            newPositionDeleteEntry(file, spec, sourcePrefix, targetPrefix, rewrittenDeleteFile);
        appendEntryWithFile(entry, writer, posDeleteFile);
        // keep the following entries in metadata but exclude them from copyPlan
        // 1) deleted position delete files
        // 2) entries not changed by snapshotIds
        if (entry.isLive() && snapshotIds.contains(entry.snapshotId())) {
          String rewrittenStagingPath =
              rewrittenDeleteFile != null ? rewrittenDeleteFile.stagingPath() : null;
          result
              .copyPlan()
              .add(
                  Pair.of(
                      rewrittenStagingPath != null
                          ? rewrittenStagingPath
                          : stagingPath(file.location(), sourcePrefix, stagingLocation),
                      posDeleteFile.location()));
        }
        result.toRewrite().add(file.copy());
        return result;
      case EQUALITY_DELETES:
        DeleteFile eqDeleteFile = newEqualityDeleteEntry(file, spec, sourcePrefix, targetPrefix);
        appendEntryWithFile(entry, writer, eqDeleteFile);
        // keep the following entries in metadata but exclude them from copyPlan
        // 1) deleted equality delete files
        // 2) entries not changed by snapshotIds
        if (entry.isLive() && snapshotIds.contains(entry.snapshotId())) {
          // No need to rewrite equality delete files as they do not contain absolute file paths.
          result.copyPlan().add(Pair.of(file.location(), eqDeleteFile.location()));
        }
        return result;

      default:
        throw new UnsupportedOperationException("Unsupported delete file type: " + file.content());
    }
  }

  private static <F extends ContentFile<F>> void appendEntryWithFile(
      ManifestEntry<F> entry, ManifestWriter<F> writer, F file) {

    switch (entry.status()) {
      case ADDED:
        writer.add(file);
        break;
      case EXISTING:
        writer.existing(
            file, entry.snapshotId(), entry.dataSequenceNumber(), entry.fileSequenceNumber());
        break;
      case DELETED:
        writer.delete(file, entry.dataSequenceNumber(), entry.fileSequenceNumber());
        break;
    }
  }

  private static DeleteFile newEqualityDeleteEntry(
      DeleteFile file, PartitionSpec spec, String sourcePrefix, String targetPrefix) {
    String path = file.location();

    if (!path.startsWith(sourcePrefix)) {
      throw new UnsupportedOperationException(
          "Expected delete file to be under the source prefix: "
              + sourcePrefix
              + " but was "
              + path);
    }
    int[] equalityFieldIds = file.equalityFieldIds().stream().mapToInt(Integer::intValue).toArray();
    String newPath = newPath(path, sourcePrefix, targetPrefix);
    return FileMetadata.deleteFileBuilder(spec)
        .ofEqualityDeletes(equalityFieldIds)
        .copy(file)
        .withPath(newPath)
        .withSplitOffsets(file.splitOffsets())
        .build();
  }

  private static DeleteFile newPositionDeleteEntry(
      DeleteFile file,
      PartitionSpec spec,
      String sourcePrefix,
      String targetPrefix,
      RewriteFileResult rewrittenDeleteFile) {
    String path = file.location();
    Preconditions.checkArgument(
        path.startsWith(sourcePrefix),
        "Expected delete file %s to start with prefix: %s",
        path,
        sourcePrefix);

    FileMetadata.Builder builder =
        FileMetadata.deleteFileBuilder(spec)
            .copy(file)
            .withPath(newPath(path, sourcePrefix, targetPrefix))
            .withMetrics(ContentFileUtil.replacePathBounds(file, sourcePrefix, targetPrefix));

    if (rewrittenDeleteFile != null) {
      builder
          .withFileSizeInBytes(rewrittenDeleteFile.fileSizeInBytes())
          .withEncryptionKeyMetadata(rewrittenDeleteFile.keyMetadata());
    }

    // Update referencedDataFile for DV files
    String newReferencedDataFile =
        rewriteReferencedDataFilePathForDV(file, sourcePrefix, targetPrefix);
    if (newReferencedDataFile != null) {
      builder.withReferencedDataFile(newReferencedDataFile);
    }

    return builder.build();
  }

  /**
   * Replace the referenced data file path for a DV (Deletion Vector) file.
   *
   * <p>For DV files, returns the updated path with the target prefix. For non-DV files or files
   * without a referenced data file, returns null.
   *
   * @param deleteFile delete file to check
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @return updated referenced data file path, or null if not applicable
   */
  private static String rewriteReferencedDataFilePathForDV(
      DeleteFile deleteFile, String sourcePrefix, String targetPrefix) {
    if (!ContentFileUtil.isDV(deleteFile) || deleteFile.referencedDataFile() == null) {
      return null;
    }

    String oldReferencedDataFile = deleteFile.referencedDataFile();
    if (oldReferencedDataFile.startsWith(sourcePrefix)) {
      return newPath(oldReferencedDataFile, sourcePrefix, targetPrefix);
    }

    return oldReferencedDataFile;
  }

  /** Class providing engine-specific methods to read and write position delete files. */
  public interface PositionDeleteReaderWriter extends Serializable {
    CloseableIterable<Record> reader(InputFile inputFile, FileFormat format, PartitionSpec spec);

    PositionDeleteWriter<Record> writer(
        OutputFile outputFile, FileFormat format, PartitionSpec spec, StructLike partition)
        throws IOException;
  }

  /**
   * Rewrite a position delete file, replacing path references.
   *
   * @param deleteFile source delete file to be rewritten
   * @param outputFile output file to rewrite delete file to
   * @param io file io
   * @param spec spec of delete file
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix to replace it
   * @param posDeleteReaderWriter class to read and write position delete files
   * @deprecated since 1.12.0, will be removed in 1.13.0; use {@link #rewritePositionDelete} which
   *     returns the size of the rewritten file so callers can record an accurate {@code
   *     file_size_in_bytes}.
   */
  @Deprecated
  public static void rewritePositionDeleteFile(
      DeleteFile deleteFile,
      OutputFile outputFile,
      FileIO io,
      PartitionSpec spec,
      String sourcePrefix,
      String targetPrefix,
      PositionDeleteReaderWriter posDeleteReaderWriter)
      throws IOException {
    rewritePositionDelete(
        deleteFile, outputFile, io, spec, sourcePrefix, targetPrefix, posDeleteReaderWriter);
  }

  /**
   * Rewrite a position delete file, replacing path references, and return the size of the rewritten
   * file.
   *
   * <p>The size is measured from the writer after it is closed (rather than via a separate {@code
   * getLength()}/HEAD call), so it is accurate even on file systems where the length of an
   * in-progress write underreports. Callers record this size as {@code file_size_in_bytes} in the
   * rewritten manifest.
   *
   * @param deleteFile source position delete file to rewrite
   * @param outputFile output file to write the rewritten delete file to
   * @param io file io
   * @param spec spec of delete file
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix to replace it
   * @param posDeleteReaderWriter class to read and write position delete files
   * @return the size in bytes of the rewritten file
   */
  public static long rewritePositionDelete(
      DeleteFile deleteFile,
      OutputFile outputFile,
      FileIO io,
      PartitionSpec spec,
      String sourcePrefix,
      String targetPrefix,
      PositionDeleteReaderWriter posDeleteReaderWriter)
      throws IOException {
    return rewritePositionDelete(
            deleteFile,
            EncryptedFiles.plainAsEncryptedOutput(outputFile),
            io,
            spec,
            sourcePrefix,
            targetPrefix,
            posDeleteReaderWriter)
        .fileSizeInBytes();
  }

  /**
   * Rewrite a position delete file, replacing path references and retaining output encryption
   * metadata.
   *
   * @param deleteFile source position delete file to rewrite
   * @param outputFile encrypted output file to write the rewritten delete file to
   * @param io file io
   * @param spec spec of delete file
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix to replace it
   * @param posDeleteReaderWriter class to read and write position delete files
   * @return the physical size and encryption metadata of the rewritten file
   */
  public static RewriteFileResult rewritePositionDelete(
      DeleteFile deleteFile,
      EncryptedOutputFile outputFile,
      FileIO io,
      PartitionSpec spec,
      String sourcePrefix,
      String targetPrefix,
      PositionDeleteReaderWriter posDeleteReaderWriter)
      throws IOException {
    String path = deleteFile.location();
    if (!path.startsWith(sourcePrefix)) {
      throw new UnsupportedOperationException(
          String.format("Expected delete file %s to start with prefix: %s", path, sourcePrefix));
    }

    // DV files (Puffin format for v3+) need special handling to rewrite internal blob metadata
    if (ContentFileUtil.isDV(deleteFile)) {
      return rewriteDVFile(deleteFile, outputFile, io, sourcePrefix, targetPrefix);
    }

    // For non-DV position delete files (v2), rewrite using the reader/writer
    InputFile sourceFile = io.newInputFile(deleteFile);
    try (CloseableIterable<Record> reader =
        posDeleteReaderWriter.reader(sourceFile, deleteFile.format(), spec)) {
      Record record = null;
      CloseableIterator<Record> recordIt = reader.iterator();

      if (recordIt.hasNext()) {
        record = recordIt.next();
      }

      if (record != null) {
        checkNoRowData(record, path);

        OutputFile writerOutputFile =
            outputFile instanceof NativeEncryptionOutputFile
                ? (NativeEncryptionOutputFile) outputFile
                : outputFile.encryptingOutputFile();
        try (PositionDeleteWriter<Record> writer =
            posDeleteReaderWriter.writer(
                writerOutputFile, deleteFile.format(), spec, deleteFile.partition())) {

          writer.write(newPositionDeleteRecord(record, sourcePrefix, targetPrefix));

          while (recordIt.hasNext()) {
            record = recordIt.next();
            if (record != null) {
              checkNoRowData(record, path);
              writer.write(newPositionDeleteRecord(record, sourcePrefix, targetPrefix));
            }
          }

          writer.close();
          DeleteFile rewrittenDeleteFile = writer.toDeleteFile();
          ByteBuffer rewrittenKeyMetadata = rewrittenDeleteFile.keyMetadata();
          EncryptionKeyMetadata outputKeyMetadata = outputFile.keyMetadata();
          if (rewrittenKeyMetadata == null
              && outputKeyMetadata != null
              && outputKeyMetadata.buffer() != null) {
            rewrittenKeyMetadata =
                deleteFile.format() == FileFormat.AVRO
                    ? encryptionKeyMetadata(
                        rewrittenDeleteFile.fileSizeInBytes(), outputKeyMetadata)
                    : outputKeyMetadata.buffer();
          }
          return new RewriteFileResult(
              rewrittenDeleteFile.fileSizeInBytes(),
              rewrittenKeyMetadata,
              rewrittenDeleteFile.location());
        }
      }
    }

    return new RewriteFileResult(0, null);
  }

  /**
   * Rewrite a DV (Deletion Vector) file, updating the referenced data file paths in blob metadata.
   *
   * @param deleteFile source DV file to be rewritten
   * @param outputFile output file to write the rewritten DV to
   * @param io file io
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix to replace it
   * @return the physical size and encryption metadata of the rewritten DV file
   */
  private static RewriteFileResult rewriteDVFile(
      DeleteFile deleteFile,
      EncryptedOutputFile outputFile,
      FileIO io,
      String sourcePrefix,
      String targetPrefix)
      throws IOException {
    List<Blob> rewrittenBlobs = Lists.newArrayList();
    try (PuffinReader reader = Puffin.read(io.newInputFile(deleteFile)).build()) {
      // Read all blobs and rewrite them with updated referenced data file paths
      for (Pair<BlobMetadata, ByteBuffer> blobPair :
          reader.readAll(reader.fileMetadata().blobs())) {
        BlobMetadata blobMetadata = blobPair.first();
        ByteBuffer blobData = blobPair.second();

        // Get the original properties and update the referenced data file path
        Map<String, String> properties = Maps.newHashMap(blobMetadata.properties());
        String referencedDataFile = properties.get("referenced-data-file");
        if (referencedDataFile != null && referencedDataFile.startsWith(sourcePrefix)) {
          String newReferencedDataFile = newPath(referencedDataFile, sourcePrefix, targetPrefix);
          properties.put("referenced-data-file", newReferencedDataFile);
        }

        // Create a new blob with updated properties
        rewrittenBlobs.add(
            new Blob(
                blobMetadata.type(),
                blobMetadata.inputFields(),
                blobMetadata.snapshotId(),
                blobMetadata.sequenceNumber(),
                blobData,
                PuffinCompressionCodec.forName(blobMetadata.compressionCodec()),
                properties));
      }
    }

    try (PuffinWriter writer =
        Puffin.write(outputFile.encryptingOutputFile())
            .createdBy(IcebergBuild.fullVersion())
            .build()) {
      rewrittenBlobs.forEach(writer::write);
      writer.close();
      ByteBuffer keyMetadata = encryptionKeyMetadata(writer.length(), outputFile.keyMetadata());
      return new RewriteFileResult(
          writer.length(), keyMetadata, outputFile.encryptingOutputFile().location());
    }
  }

  private static ByteBuffer encryptionKeyMetadata(
      long fileSizeInBytes, EncryptionKeyMetadata keyMetadata) {
    if (keyMetadata instanceof NativeEncryptionKeyMetadata nativeKeyMetadata) {
      return nativeKeyMetadata.copyWithLength(fileSizeInBytes).buffer();
    }

    return keyMetadata.buffer();
  }

  private static void checkNoRowData(Record record, String deleteFilePath) {
    Preconditions.checkArgument(
        record.get(2) == null,
        "Cannot rewrite position delete file with row data for %s",
        deleteFilePath);
  }

  private static PositionDelete newPositionDeleteRecord(
      Record record, String sourcePrefix, String targetPrefix) {
    PositionDelete delete = PositionDelete.create();
    String oldPath = (String) record.get(0);
    if (!oldPath.startsWith(sourcePrefix)) {
      throw new UnsupportedOperationException(
          "Expected delete file to be under the source prefix: "
              + sourcePrefix
              + " but was "
              + oldPath);
    }
    String newPath = newPath(oldPath, sourcePrefix, targetPrefix);
    delete.set(newPath, (Long) record.get(1));
    return delete;
  }

  /**
   * Rewrite a path by replacing its source prefix with a target prefix.
   *
   * <p>If the path equals the source prefix (representing a directory location), the result will be
   * the target prefix with a trailing separator.
   *
   * <p>Trailing separators are normalized: "/a" and "/a/" are treated as equivalent for both path
   * and sourcePrefix.
   *
   * @param path absolute path to rewrite
   * @param sourcePrefix source prefix that will be replaced
   * @param targetPrefix target prefix that will replace it
   * @return new path with source prefix replaced by target prefix
   * @throws IllegalArgumentException if path is not under or equal to sourcePrefix
   */
  public static String newPath(String path, String sourcePrefix, String targetPrefix) {
    return combinePaths(targetPrefix, relativize(path, sourcePrefix));
  }

  /**
   * Combine a base path and a relative path.
   *
   * <p>If the relative path is empty, returns the absolute path unchanged. Otherwise, ensures a
   * separator between the base and relative path.
   *
   * @param absolutePath the base path
   * @param relativePath the relative path to append (may be empty)
   * @return the combined path, or absolutePath unchanged if relativePath is empty
   */
  public static String combinePaths(String absolutePath, String relativePath) {
    return relativePath.isEmpty()
        ? absolutePath
        : maybeAppendFileSeparator(absolutePath) + relativePath;
  }

  /** Returns the file name of a path. */
  public static String fileName(String path) {
    String filename = path;
    int lastIndex = path.lastIndexOf(FILE_SEPARATOR);
    if (lastIndex != -1) {
      filename = path.substring(lastIndex + 1);
    }
    return filename;
  }

  /**
   * Compute the relative path from a prefix to a given path.
   *
   * <p>If the path is under the prefix, returns the portion after the prefix. If the path equals
   * the prefix (representing the root directory itself), returns an empty string.
   *
   * <p>Trailing separators are normalized: "/a" and "/a/" are treated as equivalent for both path
   * and prefix. This allows flexibility when paths come from different sources that may or may not
   * include trailing separators.
   *
   * @param path absolute path to relativize
   * @param prefix prefix path to remove
   * @return relative path from prefix to path, or empty string if path equals prefix
   * @throws IllegalArgumentException if path is not under or equal to prefix
   */
  public static String relativize(String path, String prefix) {
    String toRemove = maybeAppendFileSeparator(prefix);
    String normalizedPath = maybeAppendFileSeparator(path);
    if (!normalizedPath.startsWith(toRemove)) {
      throw new IllegalArgumentException(
          String.format("Path %s does not start with %s", normalizedPath, toRemove));
    }
    return normalizedPath.equals(toRemove) ? "" : path.substring(toRemove.length());
  }

  public static String maybeAppendFileSeparator(String path) {
    return path.endsWith(FILE_SEPARATOR) ? path : path + FILE_SEPARATOR;
  }

  /**
   * Construct a staging path under a given staging directory, preserving relative directory
   * structure to avoid conflicts when multiple files have the same name but different paths.
   *
   * @param originalPath source path
   * @param sourcePrefix source prefix to be replaced
   * @param stagingDir staging directory
   * @return a staging path under the staging directory that preserves the relative path structure
   */
  public static String stagingPath(String originalPath, String sourcePrefix, String stagingDir) {
    String relativePath = relativize(originalPath, sourcePrefix);
    return combinePaths(stagingDir, relativePath);
  }
}
