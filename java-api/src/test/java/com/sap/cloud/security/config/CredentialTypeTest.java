/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CredentialTypeTest {

	@Test
	public void from() {
		Assertions.assertEquals(CredentialType.X509, CredentialType.from("x509"));
		Assertions.assertEquals(CredentialType.X509_GENERATED, CredentialType.from("X509_GENERATED"));
		Assertions.assertEquals(CredentialType.X509_PROVIDED, CredentialType.from("X509_PROVIDED"));
		Assertions.assertEquals(CredentialType.X509_ATTESTED, CredentialType.from("X509_ATTESTED"));
		Assertions.assertEquals(CredentialType.X509_ATTESTED, CredentialType.from("x509_attested"));
		Assertions.assertEquals(CredentialType.INSTANCE_SECRET, CredentialType.from("instance-secret"));
		Assertions.assertEquals(CredentialType.BINDING_SECRET, CredentialType.from("binding-secret"));
	}
}