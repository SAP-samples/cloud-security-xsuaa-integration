package com.sap.cloud.security.xsuaa.mock;

import org.springframework.beans.factory.annotation.Value;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;

public class MockXsuaaServiceConfiguration extends XsuaaServiceConfigurationDefault {

	@Value("${mockxsuaaserver.url:}")
	private String mockXsuaaServerUrl;

	@Override
	public String getTokenKeyUrl(String zid, String subdomain) {
		if (!mockXsuaaServerUrl.isEmpty() && mockXsuaaServerUrl == getUaaUrl()) {
			return getUaaUrl() + "/" + subdomain + "/token_keys";
		}
		return super.getTokenKeyUrl(zid, subdomain);
	}
}