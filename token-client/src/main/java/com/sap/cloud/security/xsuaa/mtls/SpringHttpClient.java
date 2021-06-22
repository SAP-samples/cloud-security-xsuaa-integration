package com.sap.cloud.security.xsuaa.mtls;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.client.ServiceClientException;
import com.sap.cloud.security.config.ClientIdentity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Nullable;

/**
 * SpringHttpClient provides factory methods to initialize RestTemplate for
 * certificate(HTTPS) based and client secret(HTTP) based communications.
 */
public class SpringHttpClient {

	private static SpringHttpClient instance;

	private SpringHttpClient() {
	}

	public static SpringHttpClient getInstance() {
		if (instance == null) {
			instance = new SpringHttpClient();
		}
		return instance;
	}

	/**
	 * Creates a HTTP RestTemplate
	 *
	 * @return RestTemplate instance
	 */
	public RestTemplate create() {
		return new RestTemplate();
	}

	/**
	 * Creates a HTTPS RestTemplate. Used to setup HTTPS client for X.509
	 * certificate based communication. Derives certificate and private key values
	 * from ClientIdentity.
	 *
	 * @param clientIdentity
	 *            ClientIdentity of Xsuaa Service
	 * @return RestTemplate instance
	 * @throws ServiceClientException
	 *             in case HTTPS Client for certificate based authentication could
	 *             not be setup
	 */
	public RestTemplate create(@Nullable ClientIdentity clientIdentity) throws ServiceClientException {
		if (clientIdentity != null && clientIdentity.isCertificateBased()) {
			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
			requestFactory.setHttpClient(HttpClientFactory.create(clientIdentity));
			return new RestTemplate(requestFactory);
		} else {
			return new RestTemplate();
		}
	}
}
