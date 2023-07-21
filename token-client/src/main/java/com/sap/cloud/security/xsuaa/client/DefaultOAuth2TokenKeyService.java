/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.net.URI;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_APP_TID;
import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_CLIENT_ID;

public class DefaultOAuth2TokenKeyService implements OAuth2TokenKeyService {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2TokenKeyService.class);

	private final CloseableHttpClient httpClient;

	public DefaultOAuth2TokenKeyService() {
		httpClient = HttpClientFactory.create(null);
	}

	public DefaultOAuth2TokenKeyService(@Nonnull CloseableHttpClient httpClient) {
		Assertions.assertNotNull(httpClient, "httpClient is required");
		this.httpClient = httpClient;
	}

	@Override
	public String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String tenantId)
			throws OAuth2ServiceException {
		return retrieveTokenKeys(tokenKeysEndpointUri, tenantId, null);
	}

	@Override
	public String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String tenantId, @Nullable String clientId) throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		HttpUriRequest request = new HttpGet(tokenKeysEndpointUri); // lgtm[java/ssrf] tokenKeysEndpointUri is validated
																	// as part of XsuaaJkuValidator in java-security
		if (tenantId != null) {
			request.addHeader(X_APP_TID, tenantId);
		}
		if (clientId != null){
			request.addHeader(X_CLIENT_ID, clientId);
		}
		request.addHeader(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());

		LOGGER.debug("Executing token key retrieval GET request to {} with headers: {} ", tokenKeysEndpointUri,
				request.getAllHeaders());
		try (CloseableHttpResponse response = httpClient.execute(request)) {
			String bodyAsString = HttpClientUtil.extractResponseBodyAsString(response);
			int statusCode = response.getStatusLine().getStatusCode();
			if (statusCode == HttpStatus.SC_OK) {
				LOGGER.debug("Successfully retrieved token keys from {} for tenant '{}'", tokenKeysEndpointUri, tenantId);
				return bodyAsString;
			} else {
				throw OAuth2ServiceException.builder("Error retrieving token keys for x-app_tid " + tenantId)
						.withUri(tokenKeysEndpointUri)
						.withHeaders(X_APP_TID + "=" + tenantId + ", " + X_CLIENT_ID + "=" + clientId)
						.withStatusCode(statusCode)
						.withResponseBody(bodyAsString)
						.build();
			}
		} catch (IOException e) {
			throw new OAuth2ServiceException("Error retrieving token keys: " + e.getMessage());
		}
	}

}
