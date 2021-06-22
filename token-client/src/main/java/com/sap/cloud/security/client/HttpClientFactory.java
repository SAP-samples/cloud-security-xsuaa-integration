/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.token.ProviderNotFoundException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Represents a {@link CloseableHttpClient} creation interface.
 */
public interface HttpClientFactory {
	List<HttpClientFactory> services = new ArrayList() {
		{
			ServiceLoader.load(HttpClientFactory.class).forEach(this::add);
			LoggerFactory.getLogger(HttpClientFactory.class).info("loaded HttpClientFactory service providers: {}",
					this);
		}
	};

	/**
	 * Provides CloseableHttpClient based on ClientIdentity details. For
	 * ClientIdentity that is certificate based it will resolve https client using
	 * the provided ClientIdentity, if the ClientIdentity wasn't provided it will
	 * return default HttpClient.
	 *
	 * @param clientIdentity
	 *            for X.509 certificate based communication
	 *            {@link ClientCertificate} implementation of ClientIdentity
	 *            interface should be provided
	 * @return HTTP or HTTPS client
	 * @throws ServiceClientException
	 *             in case HTTPS Client could not be setup
	 */
	CloseableHttpClient createClient(ClientIdentity clientIdentity) throws ServiceClientException;

	static CloseableHttpClient create(ClientIdentity clientIdentity) throws ServiceClientException {
		if (services.isEmpty()) {
			throw new ProviderNotFoundException("No HttpClientFactory implementation found in the classpath");
		}
		return services.get(0).createClient(clientIdentity);
	}

}
