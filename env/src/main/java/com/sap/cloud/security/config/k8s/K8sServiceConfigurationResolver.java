/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.k8s.K8sConstants.*;

/**
 * The K8sServiceConfigurationResolver manages the service secret access from
 * the file system.
 */
class K8sServiceConfigurationResolver {
	private static final Logger LOGGER = LoggerFactory.getLogger(K8sServiceConfigurationResolver.class);

	private String xsuaaPath;
	private String iasPath;
	private String serviceManagerPath;

	K8sServiceConfigurationResolver() {
		resolveServiceConfigurationPaths();
	}

	/**
	 * Loads Service manager OAuth2 service configuration.
	 *
	 * @return OAuth2 service configuration
	 */
	@Nullable
	OAuth2ServiceConfiguration loadServiceManagerConfig() {
		File[] serviceBindings = new File(serviceManagerPath).listFiles();
		if (serviceBindings == null || serviceBindings.length == 0) {
			LOGGER.warn("No service-manager binding was found in {}", serviceManagerPath);
			return null;
		}
		Map<String, String> smPropertiesMap = getServiceProperties(serviceBindings[0]);
		return OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA).withProperties(smPropertiesMap).build();
	}

	/**
	 * Loads XSUAA or IAS OAuth2 service configuration.
	 *
	 * @param service
	 *            IAS or XSUAA service
	 * @return the map of service instance name and it's OAuth2 service
	 *         configurations
	 */
	Map<String, OAuth2ServiceConfiguration> loadOauth2ServiceConfig(Service service) {
		Map<String, OAuth2ServiceConfiguration> allServices = new HashMap<>();
		File[] serviceBindings = getServiceBindings(service);
		if (serviceBindings == null || serviceBindings.length == 0) {
			LOGGER.warn("No service bindings for {} service were found", service);
		} else {
			LOGGER.debug("Found {} {} service bindings", serviceBindings.length, service);
			for (File binding : serviceBindings) {
				Map<String, String> servicePropertiesMap = getServiceProperties(binding);
				if (!servicePropertiesMap.isEmpty()) {
					OAuth2ServiceConfiguration config = OAuth2ServiceConfigurationBuilder.forService(service)
							.withProperties(servicePropertiesMap)
							.build();
					allServices.put(binding.getName(), config);
				}
			}
		}
		return allServices;
	}

	@Nullable
	private File[] getServiceBindings(Service service) {
		String path = service == Service.XSUAA ? xsuaaPath : iasPath;
		LOGGER.debug("Retrieving {} service bindings from K8s secret file {}", service, path);
		return new File(path).listFiles();
	}

	private List<File> getBindingFiles(@Nonnull File binding) {
		File[] bindingFiles = new File(binding.getPath()).listFiles();
		if (bindingFiles == null || bindingFiles.length == 0) {
			LOGGER.warn("No service binding files were found for {}", binding.getName());
			return Collections.emptyList();
		}
		return Arrays.stream(bindingFiles).filter(File::isFile)
				.collect(Collectors.toList());
	}

	private Map<String, String> getServiceProperties(File binding) {
		List<File> serviceBindingFiles = getBindingFiles(binding);
		if (serviceBindingFiles.isEmpty()) {
			return Collections.emptyMap();
		}
		return mapServiceProperties(serviceBindingFiles);
	}

	private Map<String, String> mapServiceProperties(List<File> servicePropertiesList) {
		final Map<String, String> serviceProperties = new HashMap<>();
		for (final File property : servicePropertiesList) {
			try {
				final List<String> lines = readLinesFromFile(property);
				if (!lines.isEmpty()) {
					serviceProperties.put(property.getName(), String.join("\\n", lines));
				} else {
					LOGGER.warn("{} value is empty", property.getName());
				}
			} catch (IOException ex) {
				LOGGER.error("Failed to read content of service configuration property files", ex);
				return serviceProperties;
			}
		}
		LOGGER.debug("{} attributes: {}", servicePropertiesList.get(0).getParentFile().getName(), serviceProperties);
		return serviceProperties;
	}

	@Nonnull
	private static List<String> readLinesFromFile(File property) throws IOException {
		return Files.readAllLines(Paths.get(property.getAbsolutePath()));
	}

	private void resolveServiceConfigurationPaths() {
		this.xsuaaPath = getUserDefinedConfigurationPath(XSUAA_CONFIG_PATH);
		this.iasPath = getUserDefinedConfigurationPath(IAS_CONFIG_PATH);
		this.serviceManagerPath = getUserDefinedConfigurationPath(SM_CONFIG_PATH);
		if (this.xsuaaPath == null) {
			this.xsuaaPath = XSUAA_CONFIG_PATH_DEFAULT;
		}
		if (this.iasPath == null) {
			this.iasPath = IAS_CONFIG_PATH_DEFAULT;
		}
		if (this.serviceManagerPath == null) {
			this.serviceManagerPath = SERVICE_MANAGER_CONFIG_PATH_DEFAULT;
		}
	}

	@Nullable
	private String getUserDefinedConfigurationPath(String xsuaaConfigPath) {
		// Resolves also empty string as null
		if (System.getenv(xsuaaConfigPath) == null || System.getenv(xsuaaConfigPath).isEmpty()) {
			return null;
		}
		return System.getenv(xsuaaConfigPath);
	}
}
