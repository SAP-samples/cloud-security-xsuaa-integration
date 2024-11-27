/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.util.Lists.newArrayList;

public class XsuaaScopeConverterTest {

	private XsuaaScopeConverter cut;
	private String appId = "myAppId!t1785";

	@BeforeEach
	public void setUp() {
		cut = new XsuaaScopeConverter(appId);
	}

	@Test
	public void constructsWithInvalidAppId_raisesIllegalArgumentException() {
		assertThatThrownBy(() -> {
			new XsuaaScopeConverter(null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("appId must not be null or empty");

		assertThatThrownBy(() -> {
			new XsuaaScopeConverter("");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("appId must not be null or empty");
	}

	@Test
	public void oneLocalScope() {
		Collection<String> scope = newArrayList("myAppId!t1785.Read");

		Collection<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).containsExactly("Read");
	}

	@Test
	public void ignoresOtherLocalScopes() {
		Collection<String> scope = newArrayList("myAppId!t1785.Read", "Display", "Read");

		Collection<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).containsExactly("Read");
	}

	@Test
	public void scopeContainsDotAndUnderscoreAsNamespace() {
		Collection<String> scope = newArrayList("myAppId!t1785.Read.Context", "myAppId!t1785.Write.Context");

		Collection<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).containsExactly("Read.Context", "Write.Context");
	}

	@Test
	public void noScopes_emptyCollection() {
		Collection<String> scope = newArrayList();

		Collection<String> translatedScope = cut.convert(scope);

		assertThat(translatedScope).isEmpty();
	}

}
