/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.mtls.SSLContextFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Creates a {@link CloseableHttpClient} instance. Supports certificate based communication.
 */
public class DefaultHttpClientFactory implements HttpClientFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultHttpClientFactory.class);

	public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws ServiceClientException {
		LOGGER.warn("In productive environment, provide well configured HttpClientFactory service");
		if (clientIdentity != null && clientIdentity.isCertificateBased()) {
			LOGGER.debug("Setting up HTTPS client with: certificate: {}\nprivate key: {}\n",
					clientIdentity.getCertificate(), clientIdentity.getKey());

			SSLContext sslContext;
			try {
				sslContext = SSLContextFactory.getInstance().create(clientIdentity.getCertificate(),
						clientIdentity.getKey());
			} catch (IOException | GeneralSecurityException e) {
				throw new ServiceClientException(
						String.format("Couldn't set up HTTPS client for service provider. %s.%s", e.getMessage(), e));
			}
			SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
			return HttpClients.custom()
					.setSSLContext(sslContext)
					.setSSLSocketFactory(socketFactory)
					.build();
		}
		LOGGER.debug("Setting up default HTTP client");
		return HttpClients.createDefault();
	}
}
