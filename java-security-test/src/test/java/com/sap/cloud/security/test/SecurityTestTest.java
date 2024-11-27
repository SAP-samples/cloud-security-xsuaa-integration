/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Service;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class SecurityTestTest {

	private SecurityTest cut = new SecurityTest(Service.XSUAA);

	@Test
	public void wireMockServerIsNotRunningAfterTearDown() throws Exception {
		cut.setup();
		cut.tearDown();
		assertThat(cut.wireMockServer.isRunning()).isFalse();
	}

}
