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
package org.apache.iceberg.rest;

import static org.apache.iceberg.TestBase.SCHEMA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.HasTableOperations;
import org.apache.iceberg.Table;
import org.apache.iceberg.TableProperties;
import org.apache.iceberg.catalog.Namespace;
import org.apache.iceberg.catalog.SessionCatalog.SessionContext;
import org.apache.iceberg.catalog.TableIdentifier;
import org.apache.iceberg.encryption.UnitestKMS;
import org.apache.iceberg.inmemory.InMemoryCatalog;
import org.apache.iceberg.inmemory.InMemoryFileIO;
import org.apache.iceberg.io.FileIO;
import org.apache.iceberg.io.PositionOutputStream;
import org.apache.iceberg.relocated.com.google.common.collect.ImmutableMap;
import org.apache.iceberg.rest.credentials.ImmutableCredential;
import org.apache.iceberg.rest.responses.ConfigResponse;
import org.apache.iceberg.rest.responses.ErrorResponse;
import org.apache.iceberg.rest.responses.LoadTableResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class TestRESTEncryptionCredentials {
  private static final TableIdentifier TABLE = TableIdentifier.of("ns", "encrypted");
  private static final SessionContext CONTEXT =
      new SessionContext("session", "user", Map.of(), Map.of());
  private static final Map<String, String> LOCAL_KMS =
      Map.of(CatalogProperties.ENCRYPTION_KMS_IMPL, UnitestKMS.class.getName());

  @TempDir private Path warehouse;

  private InMemoryCatalog backend;
  private RESTCatalog catalog;
  private ConfigResponse configResponse = ConfigResponse.builder().build();
  private UnaryOperator<LoadTableResponse> tableResponse = UnaryOperator.identity();

  @BeforeEach
  void createBackend() {
    backend = new InMemoryCatalog();
    backend.initialize(
        "backend", Map.of(CatalogProperties.WAREHOUSE_LOCATION, warehouse.toString()));
    backend.createNamespace(TABLE.namespace());
    backend
        .buildTable(TABLE, SCHEMA)
        .withProperty(TableProperties.FORMAT_VERSION, "3")
        .withProperty(TableProperties.ENCRYPTION_TABLE_KEY, UnitestKMS.MASTER_KEY_NAME1)
        .create();
  }

  @AfterEach
  void closeCatalogs() throws IOException {
    if (catalog != null) {
      catalog.close();
    }
    backend.close();
  }

  @ParameterizedTest
  @CsvSource({
    "encryption.kms-impl, header.X-Iceberg-Access-Delegation, vended-credentials",
    "encryption.kms-impl, header.x-iceberg-access-delegation, remote-signing",
    "encryption.kms-type, header.X-Iceberg-Access-Delegation, kms-vended-credentials",
    "encryption.kms-impl, header.X-Iceberg-Access-Delegation, 'vended-credentials,remote-signing'"
  })
  void rejectsDelegationWithLocalKms(String kmsProperty, String header, String mechanism) {
    assertThatThrownBy(
            () -> initialize(Map.of(kmsProperty, UnitestKMS.class.getName(), header, mechanism)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("client-configured storage and KMS credentials");
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void rejectsDelegationFromCatalogConfiguration(boolean override) {
    ConfigResponse.Builder builder = ConfigResponse.builder();
    if (override) {
      builder.withOverride("header.X-Iceberg-Access-Delegation", "vended-credentials");
    } else {
      builder.withDefault("header.X-Iceberg-Access-Delegation", "vended-credentials");
    }
    configResponse = builder.build();

    assertThatThrownBy(() -> initialize(LOCAL_KMS))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("client-configured storage and KMS credentials");
  }

  @Test
  void rejectsLocallyConfiguredRemoteSigning() {
    assertThatThrownBy(
            () ->
                initialize(
                    ImmutableMap.<String, String>builder()
                        .putAll(LOCAL_KMS)
                        .put("s3.remote-signing-enabled", "true")
                        .put("signer.endpoint", "v1/namespaces/ns/tables/encrypted/sign")
                        .build()))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("client-configured storage and KMS credentials");
  }

  @Test
  void tableFileIOHasIndependentOwnership() throws IOException {
    tableResponse =
        response ->
            LoadTableResponse.builder()
                .withTableMetadata(response.tableMetadata())
                .addConfig("server-option", "ignored-by-file-io")
                .build();
    initialize(LOCAL_KMS);
    Table first = catalog.loadTable(TABLE);
    Table second = catalog.loadTable(TABLE);

    first.io().close();

    String path = warehouse.resolve("second-table-output").toString();
    try (PositionOutputStream output = second.io().newOutputFile(path).create()) {
      output.write(1);
    }
    assertThat(second.io().newInputFile(path).getLength()).isEqualTo(1);
  }

  @Test
  void retainsClientStorageAndKmsConfiguration() {
    configResponse =
        ConfigResponse.builder()
            .withOverride("s3.access-key-id", "catalog-access")
            .withOverride("test.kms-credential", "catalog-kms")
            .withOverride("server-option", "retained")
            .build();
    tableResponse =
        response ->
            LoadTableResponse.builder()
                .withTableMetadata(response.tableMetadata())
                .addConfig("s3.access-key-id", "table-access")
                .addConfig("s3.session-token", "table-token")
                .addConfig("s3.remote-signing-enabled", "true")
                .addConfig(
                    "gcs.oauth2.refresh-credentials-endpoint", "https://example.com/credentials")
                .build();

    initialize(
        Map.of(
            CatalogProperties.ENCRYPTION_KMS_IMPL,
            ClientConfiguredKMS.class.getName(),
            "test.kms-credential",
            "client-kms",
            "s3.access-key-id",
            "client-access"));

    Table table = catalog.loadTable(TABLE);
    assertThat(table.io().properties())
        .containsEntry("s3.access-key-id", "client-access")
        .doesNotContainKeys(
            "s3.session-token",
            "s3.remote-signing-enabled",
            "gcs.oauth2.refresh-credentials-endpoint");
    assertThat(catalog.properties()).containsEntry("server-option", "retained");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"load", "create", "create-transaction", "replace-transaction", "register"})
  void rejectsVendedStorageCredentials(String operation) {
    tableResponse =
        response ->
            LoadTableResponse.builder()
                .withTableMetadata(response.tableMetadata())
                .addCredential(
                    ImmutableCredential.builder()
                        .prefix("s3://bucket/")
                        .putConfig("s3.access-key-id", "server-access")
                        .build())
                .build();
    initialize(LOCAL_KMS);
    TableIdentifier target = TableIdentifier.of(TABLE.namespace(), "new-table");

    assertThatThrownBy(
            () -> {
              switch (operation) {
                case "load" -> catalog.loadTable(TABLE);
                case "create" -> catalog.buildTable(target, SCHEMA).create();
                case "create-transaction" -> catalog.buildTable(target, SCHEMA).createTransaction();
                case "replace-transaction" ->
                    catalog.buildTable(TABLE, SCHEMA).replaceTransaction();
                case "register" ->
                    catalog.registerTable(
                        target,
                        ((HasTableOperations) backend.loadTable(TABLE))
                            .operations()
                            .current()
                            .metadataFileLocation());
                default -> throw new IllegalArgumentException("Unknown operation: " + operation);
              }
            })
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("client-configured storage credentials");
  }

  @Test
  void rejectsRemoteSigningConfiguration() {
    tableResponse =
        response ->
            LoadTableResponse.builder()
                .withTableMetadata(response.tableMetadata())
                .withRemoteSigningConfig(
                    ImmutableRemoteSigningConfig.builder().putProperties("scope", "table").build())
                .build();
    initialize(LOCAL_KMS);

    assertThatThrownBy(() -> catalog.loadTable(TABLE))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("remote signing");
  }

  @Test
  void customFileIOReceivesClientPropertiesAndSessionContext() {
    tableResponse =
        response ->
            LoadTableResponse.builder()
                .withTableMetadata(response.tableMetadata())
                .addConfig("s3.access-key-id", "server-access")
                .build();
    AtomicReference<SessionContext> context = new AtomicReference<>();
    initialize(
        ImmutableMap.<String, String>builder()
            .putAll(LOCAL_KMS)
            .put("s3.access-key-id", "client-access")
            .build(),
        (session, properties) -> {
          context.set(session);
          FileIO fileIO = new InMemoryFileIO();
          fileIO.initialize(properties);
          return fileIO;
        });

    Table table = catalog.loadTable(TABLE);
    assertThat(table.io().properties()).containsEntry("s3.access-key-id", "client-access");
    assertThat(context.get()).isEqualTo(CONTEXT);
  }

  @Test
  void serverKmsConfigurationDoesNotEnableClientEncryption() {
    configResponse =
        ConfigResponse.builder()
            .withDefault(CatalogProperties.ENCRYPTION_KMS_IMPL, "server.only.KMS")
            .build();
    initialize(Map.of("header.X-Iceberg-Access-Delegation", "vended-credentials"));
    Table table = catalog.createTable(TableIdentifier.of(Namespace.of("ns"), "plain"), SCHEMA);
    assertThat(table.io()).isInstanceOf(InMemoryFileIO.class);
  }

  private void initialize(Map<String, String> properties) {
    initialize(properties, null);
  }

  private void initialize(
      Map<String, String> properties,
      BiFunction<SessionContext, Map<String, String>, FileIO> ioBuilder) {
    RESTCatalogAdapter adapter =
        new RESTCatalogAdapter(backend) {
          @Override
          @SuppressWarnings("unchecked")
          public <T extends RESTResponse> T execute(
              HTTPRequest request,
              Class<T> responseType,
              Consumer<ErrorResponse> errorHandler,
              Consumer<Map<String, String>> responseHeaders) {
            T response = super.execute(request, responseType, errorHandler, responseHeaders);
            if (response instanceof ConfigResponse) {
              return (T) configResponse;
            } else if (response instanceof LoadTableResponse loadTableResponse) {
              return (T) tableResponse.apply(loadTableResponse);
            }
            return response;
          }
        };
    catalog =
        new RESTCatalog(CONTEXT, config -> adapter) {
          @Override
          protected RESTSessionCatalog newSessionCatalog(
              Function<Map<String, String>, RESTClient> clientBuilder) {
            return new RESTSessionCatalog(clientBuilder, ioBuilder);
          }
        };
    catalog.initialize(
        "test",
        ImmutableMap.<String, String>builder()
            .put(CatalogProperties.FILE_IO_IMPL, InMemoryFileIO.class.getName())
            .putAll(properties)
            .build());
  }

  public static class ClientConfiguredKMS extends UnitestKMS {
    @Override
    public void initialize(Map<String, String> properties) {
      assertThat(properties).containsEntry("test.kms-credential", "client-kms");
      super.initialize(properties);
    }
  }
}
