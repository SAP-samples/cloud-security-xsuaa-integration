/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.http;

import org.junit.jupiter.api.Test;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.*;
import static com.sap.cloud.security.xsuaa.http.MediaType.APPLICATION_FORM_URLENCODED;
import static com.sap.cloud.security.xsuaa.http.MediaType.APPLICATION_JSON;
import static org.assertj.core.api.Assertions.assertThat;

public class HttpHeadersFactoryTest {

	private static final HttpHeader ACCEPT_JSON_HEADER = new HttpHeader(ACCEPT, APPLICATION_JSON.value());
	private static final HttpHeader CONTENT_TYPE_URL_ENCODED = new HttpHeader(CONTENT_TYPE,
			APPLICATION_FORM_URLENCODED.value());
	private static final HttpHeader X_ZID = new HttpHeader(HttpHeaders.X_ZID, "zoneId");
	private static final String TOKEN = "TOKEN CONTENT";

	@Test
	public void createWithoutAuthorizationHeader_containsDefaultHeaders() {
		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();
		assertThat(headers.getHeaders()).hasSize(2);
		assertThat(headers.getHeaders()).containsExactlyInAnyOrder(ACCEPT_JSON_HEADER, CONTENT_TYPE_URL_ENCODED);
	}

	@Test
	public void createWithAuthorizationBearerHeader_containsDefaultHeadersAndToken() {
		HttpHeaders headers = HttpHeadersFactory.createWithAuthorizationBearerHeader(TOKEN);
		assertThat(headers.getHeaders()).hasSize(3);
		assertThat(headers.getHeaders()).contains(ACCEPT_JSON_HEADER, CONTENT_TYPE_URL_ENCODED);
		HttpHeader tokenHeader = new HttpHeader(AUTHORIZATION, "Bearer " + TOKEN);
		assertThat(headers.getHeaders()).contains(tokenHeader);
	}

	@Test
	public void createWithXzidHeader() {
		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader().withHeader(HttpHeaders.X_ZID,
				"zoneId");
		assertThat(headers.getHeaders()).hasSize(3);
		assertThat(headers.getHeaders()).containsExactlyInAnyOrder(X_ZID, ACCEPT_JSON_HEADER, CONTENT_TYPE_URL_ENCODED);
	}

}
