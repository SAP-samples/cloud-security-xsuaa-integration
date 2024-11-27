/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.AbstractToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.JwtGenerator.*;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_APP_ID;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_CLIENT_ID;
import static com.sap.cloud.security.token.TokenClaims.*;
import static com.sap.cloud.security.token.validation.validators.JwtSignatureAlgorithm.RS256;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JwtGeneratorTest {

	private static RSAKeys keys;
	private JwtGenerator cut;

	@BeforeAll
	public static void setUpClass() throws Exception {
		keys = RSAKeys.fromKeyFiles("/publicKey.txt", "/privateKey.txt");
	}

	@BeforeEach
	public void setUp() {
		cut = JwtGenerator.getInstance(XSUAA, DEFAULT_CLIENT_ID)
				.withPrivateKey(keys.getPrivate());
	}

	@Test
	public void createXsuaaToken_setsDefaultsForTesting() {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.getHeaderParameterAsString(TokenHeader.ALGORITHM)).isEqualTo(RS256.value());
		assertThat(token.getClaimAsStringList(AUDIENCE)).containsExactly(DEFAULT_CLIENT_ID);
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(DEFAULT_CLIENT_ID); // deprecated
		assertThat(token.getClaimAsString(AUTHORIZATION_PARTY)).isEqualTo(DEFAULT_CLIENT_ID);
		assertThat(token.getClientId()).isEqualTo(DEFAULT_CLIENT_ID);
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
		assertThat(token.getAppTid()).isEqualTo(DEFAULT_ZONE_ID);
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)).isEqualTo(DEFAULT_ZONE_ID);
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
		assertThat(((AbstractToken) token).isXsuaaToken()).isTrue();
	}

	@Test
	public void createIasToken() {
		cut = JwtGenerator.getInstance(IAS, "T000310")
				.withClaimValue(SUBJECT, "P176945")
				.withClaimValue(ISSUER, "https://application.myauth.com")
				.withClaimValue(GIVEN_NAME, "john")
				.withClaimValue(FAMILY_NAME, "doe")
				.withClaimValue(EMAIL, "john.doe@email.org")
				.withClaimValue(SAP_GLOBAL_USER_ID, "1234567890")
				.withClaimValue(SAP_GLOBAL_SCIM_ID, "scim-1234567890")
				.withPrivateKey(keys.getPrivate());
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.getHeaderParameterAsString(TokenHeader.KEY_ID)).isEqualTo(DEFAULT_KEY_ID_IAS);
		assertThat(token.getClaimAsString(SAP_GLOBAL_APP_TID)).isEqualTo(DEFAULT_APP_TID);
		assertThat(token.getClaimAsString(AUDIENCE)).isEqualTo("T000310");
		assertThat(token.getClaimAsString(AUTHORIZATION_PARTY)).isEqualTo("T000310");
		assertThat(token.getClientId()).isEqualTo("T000310");
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
		assertThat(token.getClaimAsString(SAP_GLOBAL_USER_ID)).isEqualTo("1234567890");
		assertThat(token.getClaimAsString(SAP_GLOBAL_SCIM_ID)).isEqualTo("scim-1234567890");
		assertThat(token.getPrincipal().getName()).isEqualTo("1234567890");
		String encodedModulusN = Base64.getUrlEncoder()
				.encodeToString(((RSAPublicKey) keys.getPublic()).getModulus().toByteArray());
		assertThat(encodedModulusN).startsWith("AJtUGmczI7RHx3");
	}

	@Test
	public void createToken_withoutPrivateKey_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstance(IAS, "T00001234").withPrivateKey(null).createToken())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void withPrivateKey_usesPrivateKey() throws Exception {
		SignatureCalculator signatureCalculator = Mockito.mock(SignatureCalculator.class);

		when(signatureCalculator.calculateSignature(any(), any(), any())).thenReturn("sig".getBytes());

		JwtGenerator.getInstance(IAS, signatureCalculator).withPrivateKey(keys.getPrivate()).createToken();

		verify(signatureCalculator, times(1)).calculateSignature(eq(keys.getPrivate()), any(), any());
	}

	@Test
	public void withClaim_containsClaim() {
		String email = "john.doe@mail.de";

		Token token = cut
				.withClaimValue(EMAIL, email)
				.createToken();

		assertThat(token.getClaimAsString(EMAIL)).isEqualTo(email);
	}

	@Test
	public void withClaimClientId_doesNotOverwriteClientId() {
		String clientId = "myClientId";

		Token token = cut
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId) // this has changed incompatible with version
				// 2.8.0!!!
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(clientId); // for compatibility
		assertThat(token.getClientId()).isEqualTo(DEFAULT_CLIENT_ID); // client id can only be overwritten by setting
		// AUTHORIZATION_PARTY
	}

	@Test
	public void withClaimAzp_overwritesClientId() {
		String clientId = "myClientId";

		Token token = cut
				.withClaimValue(AUTHORIZATION_PARTY, clientId) // overwrite client id
				.withClaimValue(AUTHORIZATION_PARTY, clientId) // overwrites client id
				.createToken();

		assertThat(token.getClientId()).isEqualTo(clientId);
	}

	@Test
	public void withHeaderParameter_containsHeaderParameter() {
		String tokenKeyServiceUrl = "http://localhost/token_keys";
		String keyId = "theKeyId";
		Token token = cut.withHeaderParameter(TokenHeader.JWKS_URL, tokenKeyServiceUrl)
				.withHeaderParameter(TokenHeader.KEY_ID, keyId)
				.createToken();

		assertThat(token.getHeaderParameterAsString(TokenHeader.KEY_ID)).isEqualTo(keyId);
		assertThat(token.getHeaderParameterAsString(TokenHeader.JWKS_URL)).isEqualTo(tokenKeyServiceUrl);
	}

	@Test
	public void withScopes_containsScopeWhenServiceIsXsuaa() {
		String[] scopes = new String[] { "openid", "app1.scope" };
		Token token = cut.withScopes(scopes).createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)).containsExactly(scopes);
	}

	@Test
	public void withLocalScopes_containsGivenScopesAsLocalScopesWhenServiceIsXsuaa() {
		String scopeRead = "Read";
		String scopeWrite = "Write";
		Token token = cut
				.withAppId(DEFAULT_APP_ID)
				.withLocalScopes(scopeRead, scopeWrite).createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactlyInAnyOrder(DEFAULT_APP_ID + "." + scopeRead, DEFAULT_APP_ID + "." + scopeWrite);
	}

	@Test
	public void consecutiveScopeCallsOverwriteOldData() {
		String writeScope = "Write";
		String openidScope = "openid";
		Token token = cut
				.withAppId(DEFAULT_APP_ID)
				.withLocalScopes("Read")
				.withLocalScopes(writeScope)
				.withScopes("test")
				.withScopes(openidScope)
				.createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactlyInAnyOrder(openidScope, DEFAULT_APP_ID + "." + writeScope);
	}

	@Test
	public void withScopesAndLocalScopes_containsBothScopeTypes() {
		String openidScope = "openid";
		String writeScope = "Write";
		Token token = cut
				.withAppId(DEFAULT_APP_ID)
				.withLocalScopes(writeScope)
				.withScopes(openidScope)
				.createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactlyInAnyOrder(openidScope, DEFAULT_APP_ID + "." + writeScope);
	}

	@Test
	public void withLocalScopes_withoutAppId_throwsException() {
		assertThatThrownBy(() -> cut.withLocalScopes("Read").createToken())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("appId has not been set!");
	}

	@Test
	public void withScopes_serviceIsIAS_throwsUnsupportedOperationException() {
		cut = JwtGenerator.getInstance(IAS, "T00001234");
		assertThatThrownBy(() -> cut.withScopes("firstScope").createToken())
				.isInstanceOf(UnsupportedOperationException.class)
				.hasMessage("Scopes are not supported for service IAS");
	}

	@Test
	public void withExpiration_createsTokenWithExpiration() {
		Instant expiration = LocalDate.of(2019, 1, 1).atStartOfDay().toInstant(ZoneOffset.UTC);

		Token token = cut.withExpiration(expiration).createToken();

		assertThat(token.getExpiration()).isEqualTo(expiration);
	}

	@Test
	public void withClaimValuesAudience_isOverridden() {
		Token token = cut.withClaimValues(AUDIENCE, "app2", "app3").createToken();

		assertThat(token.getClaimAsStringList(AUDIENCE)).containsExactlyInAnyOrder("app2", "app3");
	}

	@Test
	public void withClaimValue_asJsonObjectContainingString() {
		Token token = cut.withClaimValue("key1", new DefaultJsonObject("{\"key2\" : \"abc\"}"))
				.createToken();

		JsonObject object = token.getClaimAsJsonObject("key1");
		assertThat(object).isNotNull();
		assertThat(object.getAsString("key2")).isEqualTo("abc");
	}

	@Test
	public void withClaimValue_asJsonObjectContainingJsonObject() {
		Token token = cut.withClaimValue("key1", new DefaultJsonObject("{\"key2\" : {\"key3\": \"theValue\"}}"))
				.createToken();

		JsonObject object = token.getClaimAsJsonObject("key1");
		assertThat(object).isNotNull();
		JsonObject innerObject = object.getJsonObject("key2");
		assertThat(innerObject).isNotNull();
		assertThat(innerObject.getAsString("key3")).isEqualTo("theValue");
	}

	@Test
	public void withClaimValue_asJsonObjectContainingList() {
		Token token = cut.withClaimValue("key1", new DefaultJsonObject("{\"key2\": [\"a\", \"b\"]}"))
				.createToken();

		JsonObject object = token.getClaimAsJsonObject("key1");
		assertThat(object).isNotNull();
		List<String> list = object.getAsList("key2", String.class);
		assertThat(list).containsExactly("a", "b");
	}

	@Test
	public void loadClaimsFromFile_doesNotContainValidJson_throwsException() {
		String resourcePath = "/emptyFile.json";
		assertThatThrownBy(() -> cut.withClaimsFromFile(resourcePath).createToken())
				.isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void loadClaimsFromFile_containsStringClaims() {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getClaimAsString(EMAIL)).isEqualTo("test@uaa.org");
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE))
				.isEqualTo("urn:ietf:params:oauth:grant-type:saml2-bearer");
	}

	@Test
	public void loadClaimsFromFile_containsExpirationClaim() {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getExpiration()).isEqualTo(Instant.ofEpochSecond(1542416800));
	}

	@Test
	public void loadClaimsFromFile_containsJsonObjectClaims() {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		JsonObject externalAttributes = token.getClaimAsJsonObject("ext_attr");

		assertThat(externalAttributes).isNotNull();
		assertThat(externalAttributes.getAsString("enhancer")).isEqualTo("XSUAA");
		assertThat(externalAttributes.getAsList("acl", String.class)).containsExactly("app1!t23");
	}

	@Test
	public void loadClaimsFromFile_containsListClaims() {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactly("openid", "testScope", "testApp.localScope");
		assertThat(token.getClaimAsStringList("empty_list")).isEmpty();
	}

	@Test
	public void getInstanceFromFile_overridesTokenPropertiesForTesting() {
		Token token = JwtGenerator.getInstanceFromFile(XSUAA, "/token.json")
				.createToken();

		assertThat(token.getHeaderParameterAsString(TokenHeader.KEY_ID)).isEqualTo(DEFAULT_KEY_ID);
		assertThat(token.getExpiration()).isEqualTo(NO_EXPIRE_DATE);
	}

	@Test
	public void getInstanceFromFile_loadsJsonData() {
		Token token = JwtGenerator.getInstanceFromFile(XSUAA, "/token.json")
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)).isEqualTo("zone-id");
		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES)).containsExactlyInAnyOrder("openid",
				"app1.scope");
		assertThat(token.getClientId()).isEqualTo("testingClientId");
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo("cidTestingClientId");
		assertThat(token.getClaimAsStringList(AUDIENCE)).containsExactly("app1.scope");
	}

	@Test
	public void getInstanceFromFile_noHeader_noErrorAndReadsPayload() {
		Token token = JwtGenerator.getInstanceFromFile(XSUAA, "/token_no_header.json")
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)).isEqualTo("zone-id");
	}

	@Test
	public void getInstanceFromFile_invalidAlg_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstanceFromFile(XSUAA, "/token_invalid_alg.json"))
				.isInstanceOf(UnsupportedOperationException.class);
	}

	@Test
	public void getInstanceFromFile_fileDoesNotExist_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstanceFromFile(XSUAA, "/doesNotExist.json"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void fromFile_fileMalformed_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstanceFromFile(XSUAA, "/publicKey.txt"))
				.isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void createToken_signatureCalculation_NoSuchAlgorithmExceptionTurnedIntoRuntimeException() {
		JwtGenerator instance = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new NoSuchAlgorithmException();
		});
		assertThatThrownBy(instance::createToken).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_SignatureExceptionTurnedIntoRuntimeException() {
		JwtGenerator instance = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new SignatureException();
		});
		assertThatThrownBy(instance::createToken).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_InvalidKeyExceptionTurnedIntoRuntimeException() {
		JwtGenerator instance = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new InvalidKeyException();
		});
		assertThatThrownBy(instance::createToken).isInstanceOf(RuntimeException.class);
	}

}
