/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class AssertionsTest {

	@Test
	public void assertNotNull_throwsIllegalArgumentExceptionContainingMessage() {
		String message = "A message";
		assertThatThrownBy(() ->
			Assertions.assertNotNull(null, message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);
	}

	@Test
	public void assertNotNull_doesNotThrow() {
		Assertions.assertNotNull(new Object(), "Should not be thrown");
	}

	@Test
	public void assertHasText_throwsIllegalArgumentExceptionContainingMessage() {
		String message = "A message";
		assertThatThrownBy(() ->
			Assertions.assertHasText(null, message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);

		assertThatThrownBy(() ->
			Assertions.assertHasText("", message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);

		assertThatThrownBy(() ->
			Assertions.assertHasText("  ", message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);
	}

	@Test
	public void assertHasText_doesNotThrow() {
		Assertions.assertHasText(" s ", "Should not be thrown");
	}

	@Test
	public void assertNotEmpty_doesNotThrow() {
		Assertions.assertNotEmpty(Collections.singletonList("one entry"), "Should not be thrown");
	}

	@Test
	public void assertNotEmpty_throwsIllegalArgumentExceptionContainingMessage() {
		String message = "A message";
		assertThatThrownBy(() ->
			Assertions.assertNotEmpty(null, message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);

		assertThatThrownBy(() ->
			Assertions.assertNotEmpty(new ArrayList<>(), message)).isInstanceOf(IllegalArgumentException.class).hasMessage(message);
	}
}
