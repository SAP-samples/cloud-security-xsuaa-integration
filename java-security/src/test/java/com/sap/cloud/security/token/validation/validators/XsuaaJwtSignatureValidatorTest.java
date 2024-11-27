/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
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

import static com.sap.cloud.security.config.ServiceConstants.XSUAA.UAA_DOMAIN;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.when;

public class XsuaaJwtSignatureValidatorTest {
	private Token xsuaaToken;
	private Token xsuaaTokenSignedWithVerificationKey; // signed with verificationkey (from configuration)

	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceConfiguration mockConfiguration;

	@BeforeEach
	public void setup() throws IOException {
		/**
		 * Header -------- { "alg": "RS256", "jku":
		 * "https://authentication.stagingaws.hanavlab.ondemand.com/token_keys", "kid":
		 * "key-id-1" } Payload -------- { "iss":
		 * "http://localhost:8080/uaa/oauth/token" }
		 */
		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", UTF_8));
		/**
		 * Header -------- { "jku": "http://localhost:65148/token_keys", "alg": "RS256"
		 * }
		 */
		xsuaaTokenSignedWithVerificationKey = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaAccessTokenRSA256_signedWithVerificationKey.txt", UTF_8));

		mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getService()).thenReturn(Service.XSUAA);
		when(mockConfiguration.getProperty(UAA_DOMAIN)).thenReturn("authentication.stagingaws.hanavlab.ondemand.com");

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(
						URI.create("https://authentication.stagingaws.hanavlab.ondemand.com/token_keys?zid=uaa"),
						Map.of(HttpHeaders.X_ZID, "uaa")))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", UTF_8));

		cut = new XsuaaJwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(Mockito.mock(OidcConfigurationService.class)));
	}

	@Test
	public void xsuaa_RSASignatureMatchesJWKS() {
		assertThat(cut.validate(xsuaaToken).isValid(), is(true));
	}

	@Test
	public void onlineVerificationFails_noVerificationKey() throws IOException {
		when(tokenKeyServiceMock
				.retrieveTokenKeys(
						URI.create("https://authentication.stagingaws.hanavlab.ondemand.com/token_keys?zid=uaa"),
						Map.of(HttpHeaders.X_ZID, "uaa")))
				.thenThrow(new OAuth2ServiceException("Error retrieving token keys"));

		ValidationResult result = cut.validate(xsuaaToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("JWKS could not be fetched"));
	}

	@Test
	public void onlineVerificationFails_withNotWorkingVerificationKey() throws IOException {
		when(tokenKeyServiceMock
				.retrieveTokenKeys(
						URI.create("https://authentication.stagingaws.hanavlab.ondemand.com/token_keys?zid=uaa"),
						Map.of(HttpHeaders.X_ZID, "uaa")))
				.thenThrow(new OAuth2ServiceException("Error retrieving token keys"));
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"""
						-----BEGIN PUBLIC KEY-----
						MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/
						oQIDAQAB
						-----END PUBLIC KEY-----""");
		ValidationResult result = cut.validate(xsuaaToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("JWKS could not be fetched"));
	}

	@Test
	public void generatedToken_SignatureMatchesVerificationkey() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"""
						-----BEGIN PUBLIC KEY-----
						MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/
						2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTN
						VTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9Y
						oU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GP
						n38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0
						frWAPyEfuIW9B+mR/2vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4
						oQIDAQAB
						-----END PUBLIC KEY-----""");
		assertThat(cut.validate(xsuaaTokenSignedWithVerificationKey).isValid(), is(true));
	}

	@Test
	public void validationFails_whenVerificationKeyIsInvalid() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn("INVALIDKEY");

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("Fallback validation key"));
	}

	@Test
	public void validationFails_whenSignatureOfGeneratedTokenDoesNotMatchVerificationkey() {
		when(mockConfiguration.hasProperty("verificationkey")).thenReturn(true);
		when(mockConfiguration.getProperty("verificationkey")).thenReturn(
				"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1QaZzMjtEfHdimrHP3/2Yr+1z685eiOUlwybRVG9i8wsgOUh+PUGuQL8hgulLZWXU5MbwBLTECAEMQbcRTNVTolkq4i67EP6JesHJIFADbK1Ni0KuMcPuiyOLvDKiDEMnYG1XP3X3WCNfsCVT9YoU+lWIrZr/ZsIvQri8jczr4RkynbTBsPaAOygPUlipqDrpadMO1momNCbea/o6GPn38LxEw609ItfgDGhL6f/yVid5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/3vGhyU9IbbWpvFXiy9RVbbsM538TCjd5JF2dJvxy24addC4oQIDAQAB-----END PUBLIC KEY-----");

		ValidationResult result = cut.validate(xsuaaTokenSignedWithVerificationKey);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(), containsString("Signature of Jwt Token is not valid"));
		assertThat(result.getErrorDescription(),
				containsString("(Signature: CetA62rQSNRj93S9mqaHrKJyzONKeEKcEJ9O5wObRD_"));
	}

}
