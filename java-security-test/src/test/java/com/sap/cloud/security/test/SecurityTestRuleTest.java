/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.ApplicationServerOptions.forService;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;

public class SecurityTestRuleTest {

	private static final int PORT = 8484;
	private static final int APPLICATION_SERVER_PORT = 8383;
	private static final String UTF_8 = StandardCharsets.UTF_8.displayName();
	private static final String PUBLIC_KEY_PATH = "/publicKey.txt";
	private static final String PRIVATE_KEY_PATH = "/privateKey.txt";

	@ClassRule
	public static SecurityTestRule cut = SecurityTestRule.getInstance(XSUAA)
			.setPort(PORT)
			.setKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH)
			.useApplicationServer(forService(XSUAA).usePort(APPLICATION_SERVER_PORT))
			.addApplicationServlet(TestServlet.class, "/hi");

	@Test
	public void getTokenKeysRequest_responseContainsExpectedTokenKeys()
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

		HttpGet httpGet = new HttpGet("http://localhost:" + PORT + "/token_keys");
		try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
			String expEncodedKey = Base64.getEncoder()
					.encodeToString(RSAKeys.loadPublicKey(PUBLIC_KEY_PATH).getEncoded());

			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);

			List<JsonObject> tokenKeys = new DefaultJsonObject(readContent(response)).getJsonObjects("keys");
			assertThat(tokenKeys).hasSize(4);
			String publicKeyFromTokenKeys = tokenKeys.get(0).getAsString("value");
			assertThat(publicKeyFromTokenKeys).isEqualTo(expEncodedKey);
			assertThat(publicKeyFromTokenKeys)
					.contains("d5pFzZQWb+9l6mCuJww0hnhO6gt6Rv98OWDty9G0frWAPyEfuIW9B+mR/2vGhyU9IbbW");

			String modulusFromTokenKeys = tokenKeys.get(0).getAsString("n"); // public key modulus
			assertThat(modulusFromTokenKeys).contains(
					"9mK_tc-vOXojlJcMm0VRvYvMLIDlIfj1BrkC_IYLpS2Vl1OTG8AS0xAgBDEG3EUzVU6JZKuIuuxD-iXrBySBQA2y");
		}
	}

	@Test
	public void generatesTokenWithOtherClaimsAndHeaderParameter() {
		Token generatedToken = cut.getPreconfiguredJwtGenerator()
				.withClaimValue(TokenClaims.ISSUER, "issuer")
				.withLocalScopes("scope1")
				.withHeaderParameter(TokenHeader.TYPE, "type").createToken();
		assertThat(generatedToken.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID))
				.isEqualTo(SecurityTestRule.DEFAULT_CLIENT_ID); // for compatibility reasons
		assertThat(generatedToken.getClientId())
				.isEqualTo(SecurityTestRule.DEFAULT_CLIENT_ID);
		assertThat(generatedToken.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactly(SecurityTestRule.DEFAULT_APP_ID + ".scope1");
		assertThat(generatedToken.getClaimAsString(TokenClaims.ISSUER)).isEqualTo("issuer");
		assertThat(generatedToken.getHeaderParameterAsString(TokenHeader.TYPE)).isEqualTo("type");
	}

	@Test
	public void testRuleIsInitializedCorrectly() {
		assertThat(cut.getApplicationServerUri()).isEqualTo("http://localhost:" + APPLICATION_SERVER_PORT);
		assertThat(cut.getWireMockServer()).isNotNull();
		assertThat(cut.createToken().getTokenValue())
				.isEqualTo(cut.getPreconfiguredJwtGenerator().createToken().getTokenValue());
	}

	@Test
	public void getPreconfiguredJwtGenerator_tokenHasExpirationDate() {
		Token token = cut.getPreconfiguredJwtGenerator().createToken();

		assertThat(token.hasClaim(TokenClaims.EXPIRATION)).isTrue();
	}

	@Test
	public void getPreconfiguredJwtGenerator_tokenHasCorrectIssuer() {
		Token token = cut.getPreconfiguredJwtGenerator().createToken();

		assertThat(token.getClaimAsString(TokenClaims.ISSUER)).isEqualTo(cut.base.wireMockServer.baseUrl());
	}

	@Test
	public void getConfigurationBuilderFromFile_configurationHasCorrectUrl() {
		OAuth2ServiceConfiguration configuration = cut
				.getOAuth2ServiceConfigurationBuilderFromFile("/vcapServices/vcapSimple.json")
				.build();

		assertThat(configuration.getUrl()).isNotNull();
		assertThat(configuration.getUrl().toString()).isEqualTo(cut.base.wireMockServer.baseUrl());
	}

	@Test
	public void getJwtGeneratorFromFile_setsTestingDefaults() {
		Token token = cut.getJwtGeneratorFromFile("/token.json").createToken();

		String baseUrl = cut.base.wireMockServer.baseUrl();
		URI jwksUrl = new XsuaaDefaultEndpoints(baseUrl, null).getJwksUri();
		assertThat(token.getHeaderParameterAsString(TokenHeader.JWKS_URL)).isEqualTo(jwksUrl.toString());
		assertThat(token.getClaimAsString(TokenClaims.ISSUER)).isEqualTo(baseUrl);
	}

	@Test
	public void setKeys_invalidPath_throwsException() {
		assertThatThrownBy(() -> SecurityTestRule.getInstance(XSUAA)
				.setKeys("doesNotExist", "doesNotExist"))
				.isInstanceOf(RuntimeException.class);
	}

	@Test
	public void getContext() {
		assertThat(cut.getContext()).isNotNull();
	}

	public static class SecurityTestRuleWithMockServlet {

		private HttpServlet mockServlet = Mockito.mock(HttpServlet.class);

		@Rule
		public SecurityTestRule mockServletRule = SecurityTestRule.getInstance(XSUAA)
				.useApplicationServer()
				.addApplicationServlet(new ServletHolder(mockServlet), "/");

		@Test
		public void testThatServletMethodIsNotCalled() throws ServletException, IOException {
			HttpGet httpGet = new HttpGet(mockServletRule.getApplicationServerUri());
			try (CloseableHttpResponse response = HttpClients.createDefault().execute(httpGet)) {
				assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
			}
			Mockito.verify(mockServlet, Mockito.times(0)).service(any(), any());
		}

	}

	public static class SecurityTestRuleWithoutApplicationServer {

		@Rule
		public SecurityTestRule rule = SecurityTestRule.getInstance(XSUAA);

		@Test
		public void testRuleIsInitializedCorrectly() {
			assertThat(rule.getApplicationServerUri()).isNull();
			assertThat(rule.getWireMockServer()).isNotNull();
		}
	}

	public static class SecurityTestRuleApplicationServer_IAS {

		@Rule
		public SecurityTestRule rule = SecurityTestRule.getInstance(IAS);

		@Test
		public void testRuleIsInitializedCorrectly() {
			assertThat(rule.getApplicationServerUri()).isNull();
			assertThat(rule.getWireMockServer()).isNotNull();
		}

	}

	public static class TestServlet extends HttpServlet {
		@Override
		protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
			response.setStatus(HttpServletResponse.SC_OK);
			response.setContentType("text/plain");
			response.setCharacterEncoding(UTF_8);
			response.getWriter().print("Hi!");
		}
	}

	private static String readContent(CloseableHttpResponse response) throws IOException {
		return IOUtils.readLines(response.getEntity().getContent(), UTF_8).stream()
				.collect(Collectors.joining());
	}

}