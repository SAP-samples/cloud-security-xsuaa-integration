/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

public class ClientCredentialsTest {
	ClientIdentity cut = new ClientCredentials("clientId", "clientSecret");

	@Test
	public void equals() {
		assertThat(cut.equals(cut), is(true));
		assertThat(cut.equals(new ClientCredentials("clientId", "clientSecret")), is(true));
	}

	@Test
	public void not_equals() {
		assertThat(cut.equals(new ClientCredentials("clientId2", "clientSecret")), is(false));
		assertThat(cut.equals(new ClientCredentials("clientId", "clientSecret2")), is(false));
		assertThat(cut.equals(null), is(false));
		assertThat(cut.equals(new Object()), is(false));
	}

	@Test
	public void hashCoded() {
		int cutHashCode = cut.hashCode();
		assertThat(cutHashCode, is(not(0)));
		assertThat(cutHashCode, is(new ClientCredentials("clientId", "clientSecret").hashCode()));
		assertThat(cutHashCode, is(not(new ClientCredentials("clientId2", "clientSecret").hashCode())));
	}

	@Test
	public void stringify() {
		assertThat(cut.toString(), is("clientId:clientSecret"));
	}

	@Test
	public void testClientIdentityResolution() {
		assertTrue(cut.isValid());
		assertFalse(cut.isCertificateBased());
		assertNull(cut.getCertificate());
		assertNull(cut.getKey());
		assertEquals("clientId", cut.getId());
		assertEquals("clientSecret", cut.getSecret());
	}
}
