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
 * Creates a {@link CloseableHttpClient} instance. Supports certificate based
 * communication.
 */
public class DefaultHttpClientFactory implements HttpClientFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultHttpClientFactory.class);

	public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		LOGGER.warn("In productive environment provide well configured HttpClientFactory service");
		if (clientIdentity != null && clientIdentity.isCertificateBased()) {
			LOGGER.debug("Setting up HTTPS client with: certificate: {}\n", clientIdentity.getCertificate());
			SSLContext sslContext;
			try {
				sslContext = SSLContextFactory.getInstance().create(clientIdentity);
			} catch (IOException | GeneralSecurityException e) {
				throw new HttpClientException(
						String.format("Couldn't set up https client for service provider. %s.",
								e.getLocalizedMessage()));
			}
			SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(sslContext);
			return HttpClients.custom()
					.setSSLContext(sslContext)
					.setSSLSocketFactory(socketFactory)
					.build();
		}
		LOGGER.debug("Setting up default http client");
		return HttpClients.createDefault();
	}
}
