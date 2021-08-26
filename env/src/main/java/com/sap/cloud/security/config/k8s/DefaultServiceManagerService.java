/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * The DefaultServiceManagerService fetches information about service instances
 * and service instance plans.
 */
class DefaultServiceManagerService {
	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultServiceManagerService.class);
	private static final String SERVICE_PLANS = "/v1/service_plans";
	private static final String SERVICE_INSTANCES = "/v1/service_instances";

	private final CloseableHttpClient httpClient;
	private final OAuth2ServiceConfiguration smConfiguration;
	private final OAuth2TokenService defaultOAuth2TokenService;

	DefaultServiceManagerService(OAuth2ServiceConfiguration smConfiguration) {
		this(smConfiguration, HttpClientFactory.create(smConfiguration.getClientIdentity()));
	}

	DefaultServiceManagerService(OAuth2ServiceConfiguration smConfiguration, CloseableHttpClient httpClient) {
		this.smConfiguration = smConfiguration;
		this.httpClient = httpClient;
		this.defaultOAuth2TokenService = new DefaultOAuth2TokenService(this.httpClient);
	}

	Map<String, String> getServiceInstancePlans() {
		Map<String, String> servicePlans = getServicePlans();
		Map<String, String> serviceInstances = getServiceInstances();
		serviceInstances.keySet().forEach(k -> serviceInstances.put(k, servicePlans.get(serviceInstances.get(k))));
		LOGGER.debug("Service Instances with plan names: {}", serviceInstances);
		return serviceInstances;
	}

	// TODO make private, adjust tests
	Map<String, String> getServicePlans() {
		HttpUriRequest request = RequestBuilder.create("GET")
				.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + retrieveAccessToken())
				.setUri(smConfiguration.getProperty("sm_url") + SERVICE_PLANS)
				.build();
		Map<String, String> servicePlanMap = new HashMap<>();
		try {
			JSONArray responseArray = executeRequest(request);
			responseArray.forEach(plan -> servicePlanMap.put((String) ((JSONObject) plan).get("id"),
					(String) ((JSONObject) plan).get("name")));
		} catch (OAuth2ServiceException e) {
			e.printStackTrace();
		}
		LOGGER.debug("Service plans: {}", servicePlanMap);
		return servicePlanMap;
	}

	// TODO make private, adjust tests
	Map<String, String> getServiceInstances() {
		HttpUriRequest request = RequestBuilder.create("GET")
				.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + retrieveAccessToken())
				.setUri(smConfiguration.getProperty("sm_url") + SERVICE_INSTANCES)
				.build();
		Map<String, String> serviceInstanceMap = new HashMap<>();
		try {
			JSONArray responseArray = executeRequest(request);
			responseArray.forEach(plan -> serviceInstanceMap.put((String) ((JSONObject) plan).get("name"),
					(String) ((JSONObject) plan).get("service_plan_id")));
		} catch (OAuth2ServiceException e) {
			e.printStackTrace();
		}
		LOGGER.debug("Service instances: {}", serviceInstanceMap);
		return serviceInstanceMap;
	}

	private JSONArray executeRequest(HttpUriRequest httpRequest) throws OAuth2ServiceException {
		LOGGER.debug("Executing Http request to {} with headers {}", httpRequest.getURI(),
				httpRequest.getAllHeaders());
		try (CloseableHttpResponse response = httpClient.execute(httpRequest)) {
			int statusCode = response.getStatusLine().getStatusCode();
			LOGGER.debug("Received statusCode {} from {}", statusCode, httpRequest.getURI());
			if (statusCode == HttpStatus.SC_OK) {
				return handleResponse(response);
			} else {
				String responseBodyAsString = HttpClientUtil.extractResponseBodyAsString(response);
				LOGGER.debug("Received response body: {}", responseBodyAsString);
				throw OAuth2ServiceException.builder("Error accessing service-manager endpoint")
						.withStatusCode(statusCode)
						.withUri(httpRequest.getURI())
						.withResponseBody(responseBodyAsString)
						.build();
			}
		} catch (OAuth2ServiceException e) {
			throw e;
		} catch (IOException e) {
			throw new OAuth2ServiceException(String.format("Unexpected error accessing service-manager endpoint %s: %s",
					httpRequest.getURI(), e.getMessage()));
		}
	}

	private JSONArray handleResponse(HttpResponse response) throws IOException {
		String responseBody = HttpClientUtil.extractResponseBodyAsString(response);
		return new JSONObject(responseBody).getJSONArray("items");
	}

	@Nullable
	private String retrieveAccessToken() {
		try {
			OAuth2TokenResponse oAuth2TokenResponse = defaultOAuth2TokenService
					.retrieveAccessTokenViaClientCredentialsGrant(smConfiguration.getUrl().resolve("/oauth/token"),
							smConfiguration.getClientIdentity(), null, null, null, false);
			return oAuth2TokenResponse.getAccessToken();
		} catch (OAuth2ServiceException e) {
			LOGGER.warn("Couldn't retrieve access token for service manager.", e);
			return null;
		}
	}
}
