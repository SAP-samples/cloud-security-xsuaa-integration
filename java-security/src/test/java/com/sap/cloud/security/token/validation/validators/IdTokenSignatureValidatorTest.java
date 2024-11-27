/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

public class IdTokenSignatureValidatorTest {
	private Token iasToken;

	private JwtSignatureValidator cut;
	private OAuth2ServiceConfiguration mockConfiguration;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	OAuth2ServiceEndpointsProvider endpointsProviderMock;
	private OidcConfigurationService oidcConfigurationServiceMock;
	private static final URI JKU_URI = URI.create("https://application.myauth.com/jwks_uri");
	private static final URI DISCOVERY_URI = URI
			.create("https://application.myauth.com" + OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT);
	private static final String APP_TID = "the-app-tid";
	private static final String CLIENT_ID = "client-id";
	private static final String AZP = "T000310";
	private static final Map<String, String> PARAMS = Map.of(
			HttpHeaders.X_APP_TID, APP_TID,
			HttpHeaders.X_CLIENT_ID, CLIENT_ID,
			HttpHeaders.X_AZP, AZP);

	@BeforeEach
	public void setup() throws IOException {
		/**
		 * Header -------- { "alg": "RS256" } Payload -------- { "iss":
		 * "https://application.myauth.com" }
		 */
		iasToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));

		mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getService()).thenReturn(Service.IAS);
		when(mockConfiguration.getClientId()).thenReturn(CLIENT_ID);

		endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(JKU_URI);

		oidcConfigurationServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigurationServiceMock.retrieveEndpoints(DISCOVERY_URI))
				.thenReturn(endpointsProviderMock);

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(JKU_URI, PARAMS))
				.thenReturn(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));

		cut = new SapIdJwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(oidcConfigurationServiceMock));
	}

	@Test
	public void validates_RSASignatureMatchesJWKS() {
		assertThat(cut.validate(iasToken).isValid(), is(true));
	}

	@Test
	public void validationFails_WhenEndpointProvidesNullJku() {
		when(endpointsProviderMock.getJwksUri()).thenReturn(null);

		ValidationResult result = cut.validate(iasToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("OIDC .well-known response did not contain JWKS URI"));
	}

	@Test
	public void validationFails_whenOAuthServerIsUnavailable_OIDC() throws OAuth2ServiceException {
		when(oidcConfigurationServiceMock
				.retrieveEndpoints(any())).thenThrow(OAuth2ServiceException.class);

		ValidationResult result = cut.validate(iasToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("JWKS could not be fetched"));
	}

	@Test
	public void validationFails_whenOAuthServerIsUnavailable_JKS() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any(), anyMap())).thenThrow(OAuth2ServiceException.class);

		ValidationResult result = cut.validate(iasToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("JWKS could not be fetched"));
	}

	@Test
	public void validationFails_whenNoMatchingKey() {
		String otherKid = "someOtherKid";
		Token tokenSpy = Mockito.spy(iasToken);
		doReturn(otherKid).when(tokenSpy).getHeaderParameterAsString(JsonWebKeyConstants.KID_PARAMETER_NAME);

		ValidationResult result = cut.validate(tokenSpy);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("Key with kid " + otherKid + " not found in JWKS"));
	}

}
