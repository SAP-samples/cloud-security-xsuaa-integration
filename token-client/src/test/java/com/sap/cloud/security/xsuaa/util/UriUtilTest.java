/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class UriUtilTest {

	private final URI tokenEndpointUri = URI.create("https://subdomain.myauth.com/mypath");

	@Test
	public void replaceSubdomain_replacesNothingWhenSubdomainIsNull() {
		URI replacedURI = UriUtil.replaceSubdomain(tokenEndpointUri, null);
		assertThat(replacedURI, is(tokenEndpointUri));
	}

	@Test
	public void replaceSubdomain() {
		URI replacedURI = UriUtil.replaceSubdomain(tokenEndpointUri, "newsubdomain");
		assertThat(replacedURI.toString(), is("https://newsubdomain.myauth.com/mypath"));
	}

	@Test
	public void replaceSubdomain_replacesNothingWhenSubdomainIsEmpty() {
		URI replacedURI = UriUtil.replaceSubdomain(tokenEndpointUri, "");
		assertThat(replacedURI, is(tokenEndpointUri));
	}

	@Test
	public void replaceSubdomain_replacesNothingWhenUrlContainsNoSubdomain() {
		URI replacedURI = UriUtil.replaceSubdomain(URI.create("http://localhost"), "newsubdomain");
		assertThat(replacedURI.toString(), is("http://localhost"));
	}

	@Test
	public void replaceSubdomain_noUrlSchemaGiven() {
		URI replacedURI = UriUtil.replaceSubdomain(URI.create("localhost"), "newsubdomain");
		assertThat(replacedURI.toString(), is("localhost"));
	}
}
