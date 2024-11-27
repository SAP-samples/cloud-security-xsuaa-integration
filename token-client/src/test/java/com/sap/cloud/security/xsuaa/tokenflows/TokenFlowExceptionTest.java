/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class TokenFlowExceptionTest {

	static final String MESSAGE = "Message";
	static final Exception CAUSE = new Exception();

	@Test
	public void constructors() {

		TokenFlowException ex = new TokenFlowException();
		assertNull(ex.getMessage(), "Exception should not have any message.");
		assertNull(ex.getCause(), "Exception should not have any cause.");

		ex = new TokenFlowException(MESSAGE);
		assertNotNull(ex.getMessage(), "Exception should have a message.");
		assertNull(ex.getCause(), "Exception should not have any cause.");

		ex = new TokenFlowException(CAUSE);
		assertNotNull(ex.getMessage(), "Exception should not have a default message.");
		assertNotNull(ex.getCause(), "Exception should have a cause.");

		ex = new TokenFlowException(MESSAGE, CAUSE);
		assertNotNull(ex.getMessage(), "Exception should have a message.");
		assertNotNull(ex.getCause(), "Exception should have a cause.");
	}

}
