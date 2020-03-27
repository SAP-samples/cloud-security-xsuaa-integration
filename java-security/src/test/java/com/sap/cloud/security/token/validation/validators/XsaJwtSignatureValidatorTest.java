package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

public class XsaJwtSignatureValidatorTest {
	private Token xsaToken;

	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceConfiguration mockConfiguration;
	private static final URI PROVIDER_URI = URI.create("https://myauth.com");
	private static final URI JKU_URI = URI.create("https://myauth.com/token_keys");

	@Before
	public void setup() throws IOException {
		/**
		 * Header -------- { "alg": "RS256", } Payload -------- { "iss":
		 * "http://xsa-a272d86a-0f74-448c-93d1-6b78903d1543/UAA/oauth/token" }
		 */
		xsaToken = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaXsaAccessTokenRSA256_signedWithVerificationKey.txt", UTF_8));

		mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getService()).thenReturn(Service.XSUAA);
		when(mockConfiguration.isLegacyMode()).thenReturn(true);
		when(mockConfiguration.getUrl()).thenReturn(PROVIDER_URI);

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(JKU_URI))
						.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));

		cut = new JwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(Mockito.mock(OidcConfigurationService.class)));
	}

	@Test
	public void xsuaa_RSASignatureMatchesJWKS() {
		assertThat(cut.validate(xsaToken).isValid(), is(true));
	}
}
