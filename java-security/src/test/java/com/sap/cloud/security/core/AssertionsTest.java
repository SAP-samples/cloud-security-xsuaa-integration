/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.core;

import org.junit.jupiter.api.Test;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AssertionsTest {

	@Test
	public void assertNotNull_throwsIllegalArgumentExceptionContainingMessage() {
		String message = "A message";
		assertThatThrownBy(() ->
			assertNotNull(null, message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);
	}

	@Test
	public void assertNotNull_doesNotThrow() {
		assertNotNull(new Object(), "Should not be thrown");
	}

	@Test
	public void assertNotEmpty_throwsIllegalArgumentExceptionContainingMessage() {
		String message = "A message";
		assertThatThrownBy(() ->
			assertHasText(null, message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);

		assertThatThrownBy(() ->
			assertHasText("", message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);

		assertThatThrownBy(() ->
			assertHasText("  ", message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);
	}

	@Test
	public void assertNotEmpty_doesNotThrow() {
		assertHasText(" s ", "Should not be thrown");
	}
}
