/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DefaultServiceManagerServiceTest {
	static DefaultServiceManagerService cut;

	@BeforeAll
	static void beforeAll() {
		Map<String, String> serviceInstanceMap = new HashMap<>();
		serviceInstanceMap.put("xsuaa-application", "037e7df6-5843-4174-9cb4-69a1f9a4da7e");
		serviceInstanceMap.put("xsuaa-broker", "bb769fcb-c8b9-4612-beac-18be9743a3b7");

		Map<String, String> servicePlanMap = new HashMap<>();
		servicePlanMap.put("bb769fcb-c8b9-4612-beac-18be9743a3b7", "broker");
		servicePlanMap.put("037e7df6-5843-4174-9cb4-69a1f9a4da7e", "application");
		servicePlanMap.put("12345678-1234-1234-abcd-123456789123", "another-plan");

		cut = mock(DefaultServiceManagerService.class);
		when(cut.getServicePlans()).thenReturn(servicePlanMap);
		when(cut.getServiceInstances()).thenReturn(serviceInstanceMap);
		when(cut.getServiceInstancePlans()).thenCallRealMethod();
	}

	@Test
	void getServiceInstancePlans() {
		Map<String, String> instancePlans = cut.getServiceInstancePlans();
		assertEquals(2, instancePlans.size());
		assertEquals("application", instancePlans.get("xsuaa-application"));
		assertEquals("broker", instancePlans.get("xsuaa-broker"));
	}

}