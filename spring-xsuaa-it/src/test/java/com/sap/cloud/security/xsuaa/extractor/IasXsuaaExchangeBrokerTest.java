package com.sap.cloud.security.xsuaa.extractor;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = { TokenBrokerTestConfiguration.class })
public class IasXsuaaExchangeBrokerTest {

	@Autowired
	private OAuth2TokenService oAuth2TokenService;

	private MockHttpServletRequest request;
	private static IasXsuaaExchangeBroker cut;
	private static final String XSUAA_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHRfYXR0ciI6eyJlbmhhbmNlciI6IlhTVUFBIn19._cocFCqqATDXx6eBUoF22W9F8VwUVYY59XdLGdEDFso";
	private static final String IAS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJjbGllbnRfaWQiOiJzYi1qYXZhLWhlbGxvLXdvcmxkIiwiY2lkIjoic2ItamF2YS1oZWxsby13b3JsZCIsImF6cCI6InNiLWphdmEtaGVsbG8td29ybGQiLCJncmFudF90eXBlIjoiY2xpZW50X2NyZWRlbnRpYWxzIiwidXNlcl9pZCI6IjEwMDIxOTEiLCJ1c2VyX25hbWUiOiJXT0xGR0FORyIsImVtYWlsIjoiV09MRkdBTkdAdW5rbm93biIsImlhdCI6MTQ0MjkxMjI0NCwiZXhwIjoxNDQyOTU1MzIyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIiwiZXh0X2F0dHIiOnsic2VydmljZWluc3RhbmNlaWQiOiJhYmNkMTIzNCJ9LCJ6aWQiOiJ6b25lSWQifQ.uzdP2WyfullaZ_5aSjMr2shTfyqqXxbfgShjtfPjigY";

	@Before
	public void setUp() {
		request = new MockHttpServletRequest();
		cut = new IasXsuaaExchangeBroker(getXsuaaServiceConfiguration(), oAuth2TokenService);
	}

	@Test
	public void xsuaaTokenResolutionTest() {
		request.addHeader("Authorization", "bearer " + XSUAA_TOKEN);
		String token = cut.resolve(request);

		assertThat(token).isEqualTo(XSUAA_TOKEN);
	}

	@Test
	public void iasTokenResolutionTest() {
		request.addHeader("Authorization", "bearer " + IAS_TOKEN);
		String token = cut.resolve(request);

		assertThat(token).isEqualTo(XSUAA_TOKEN);
	}

	@Test(expected = InvalidBearerTokenException.class)
	public void invalidAuthorizationHeaderTest() {
		request.addHeader("Authorization", IAS_TOKEN);
		cut.resolve(request);
	}

	@Test(expected = InvalidBearerTokenException.class)
	public void invalidAuthorizationHeader2Test() {
		request.addHeader("Auth", "bearer " + IAS_TOKEN);
		cut.resolve(request);
	}

	private XsuaaServiceConfiguration getXsuaaServiceConfiguration() {
		XsuaaServiceConfigurationDummy cfg = new XsuaaServiceConfigurationDummy();
		cfg.appId = "a1!123";
		cfg.clientId = "myclient!t1";
		cfg.clientSecret = "top.secret";
		cfg.uaaDomain = "auth.com";
		cfg.uaaUrl = "https://mydomain.auth.com:8443";
		return cfg;
	}
}
