/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SystemStubsExtension.class)
class EnvironmentsK8sTest {

	private static final String KUBERNETES_SERVICE_HOST = "KUBERNETES_SERVICE_HOST";
	private static final String K8S_HOST_VALUE = "0.0.0.0";

	@Test
	void getCurrent_returnsOnlySingleK8sInstance(EnvironmentVariables environmentVariables) {
		environmentVariables.set(KUBERNETES_SERVICE_HOST, K8S_HOST_VALUE);

		Environment firstEnvironment = Environments.getCurrent();
		Environment secondEnvironment = Environments.getCurrent();

		assertThat(firstEnvironment).isSameAs(secondEnvironment);
		assertThat(firstEnvironment.getType()).isSameAs(Environment.Type.KUBERNETES);
	}

	@Test
	void getCurrent_returnsK8s(EnvironmentVariables environmentVariables) {
		environmentVariables.set(KUBERNETES_SERVICE_HOST, K8S_HOST_VALUE);
		Environment cut = Environments.getCurrent();
		assertThat(cut.getType()).isEqualTo(Environment.Type.KUBERNETES);
	}

}
