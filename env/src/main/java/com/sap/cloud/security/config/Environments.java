/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFEnvironment;
import com.sap.cloud.security.config.k8s.K8sEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Scanner;

import static com.sap.cloud.security.config.k8s.K8sConstants.KUBERNETES_SERVICE_HOST;

/**
 * Central entry point to access the current SAP Cloud Platform
 * {@link Environment}.
 */
public class Environments {

	private static final Logger LOGGER = LoggerFactory.getLogger(Environments.class);

	private static Environment cfEnvironment; // singleton
	private static Environment k8sEnvironment; // singleton
	private static Boolean isK8sEnv;

	private Environments() {
		// use factoryMethods instead
	}

	/**
	 * Determines the current type of {@link Environment}.
	 * 
	 * @return the current environment
	 */
	public static Environment getCurrent() {
		if (isK8sEnv()) {
			LOGGER.debug("K8s environment detected");
			return getK8sEnvironment();
		} else {
			LOGGER.debug("CF environment detected");
			return getCfEnvironment();
		}
	}

	private static Environment getCfEnvironment() {
		if (cfEnvironment == null) {
			cfEnvironment = CFEnvironment.getInstance();
		}
		return cfEnvironment;
	}

	private static Environment getK8sEnvironment() {
		if (k8sEnvironment == null) {
			k8sEnvironment = K8sEnvironment.getInstance();
		}
		return k8sEnvironment;
	}

	/**
	 * Reads {@link Environment} not from system environment but from
	 * {@link InputStream}. Is applicable only to CF environment and expects the
	 * input to be in VCAP services format.
	 * 
	 * @param input
	 *            e.g. from file
	 * @return the environment
	 */
	public static Environment readFromInput(InputStream input) {
		Scanner scanner = new Scanner(input);
		StringBuilder vcapServices = new StringBuilder();
		while (scanner.hasNext()) {
			vcapServices.append(scanner.nextLine());
		}
		return CFEnvironment.getInstance(str -> vcapServices.toString(), str -> null);
	}

	private static boolean isK8sEnv() {
		if (isK8sEnv == null) {
			isK8sEnv = System.getenv().get(KUBERNETES_SERVICE_HOST) != null;
		}
		return isK8sEnv;
	}

}
