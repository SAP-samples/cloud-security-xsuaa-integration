/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ServiceTest {

	@Test
	public void getCFNameOfIas_shouldReturnCorrectName() {
		assertThat(Service.IAS.getCFName()).isEqualTo("identity");
	}

	@Test
	public void getCFNameOfXsuaa_shouldReturnCorrectName() {
		assertThat(Service.XSUAA.getCFName()).isEqualTo("xsuaa");
	}

}
