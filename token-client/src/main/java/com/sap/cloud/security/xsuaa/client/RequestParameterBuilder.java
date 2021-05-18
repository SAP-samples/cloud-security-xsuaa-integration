package com.sap.cloud.security.xsuaa.client;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

class RequestParameterBuilder {

	private final Map<String, String> parameters = new HashMap<>();

	public RequestParameterBuilder withGrantType(String grantType) {
		parameters.put(GRANT_TYPE, grantType);
		return this;
	}

	public RequestParameterBuilder withClientId(String clientId) {
		parameters.put(PARAMETER_CLIENT_ID, clientId);
		return this;
	}

	public RequestParameterBuilder withRefreshToken(String refreshToken) {
		parameters.put(REFRESH_TOKEN, refreshToken);
		return this;
	}

	/**
	 * @deprecated use {{@link #withClientIdentity(ClientIdentity)}} instead
	 */
	@Deprecated
	public RequestParameterBuilder withClientCredentials(ClientCredentials clientCredentials) {
		parameters.put(CLIENT_ID, clientCredentials.getId());
		parameters.put(CLIENT_SECRET, clientCredentials.getSecret());
		return this;
	}

	public RequestParameterBuilder withClientIdentity(ClientIdentity clientIdentity) {
		parameters.put(CLIENT_ID, clientIdentity.getId());
		if (clientIdentity.isCertificateBased()) {
			return this;
		}
		parameters.put(CLIENT_SECRET, clientIdentity.getSecret());
		return this;
	}

	public RequestParameterBuilder withOptionalParameters(Map<String, String> optionalParameters) {
		Optional.ofNullable(optionalParameters).orElse(Collections.emptyMap())
				.forEach(parameters::putIfAbsent);
		return this;
	}

	public RequestParameterBuilder withUsername(String username) {
		parameters.put(USERNAME, username);
		return this;
	}

	public RequestParameterBuilder withPassword(String password) {
		parameters.put(PASSWORD, password);
		return this;
	}

	public RequestParameterBuilder withToken(String token) {
		parameters.put(ASSERTION, token);
		return this;
	}

	public Map<String, String> buildAsMap() {
		return parameters;
	}
}
