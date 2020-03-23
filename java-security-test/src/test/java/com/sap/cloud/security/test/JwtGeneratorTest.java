package com.sap.cloud.security.test;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.TokenHeader;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.apache.commons.io.IOUtils;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;
import sun.security.rsa.RSAPublicKeyImpl;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.test.JwtGenerator.SignatureCalculator;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_APP_ID;
import static com.sap.cloud.security.test.SecurityTestRule.DEFAULT_CLIENT_ID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class JwtGeneratorTest {

	private static RSAKeys keys;
	private JwtGenerator cut;
	private Properties originalSystemProperties;

	private static final Path RESOURCES_PATH = Paths.get(JwtGeneratorTest.class.getResource("/").getPath());

	@ClassRule
	public static TemporaryFolder temporaryFolder = new TemporaryFolder(RESOURCES_PATH.toFile());

	@BeforeClass
	public static void setUpClass() throws Exception {
		keys = RSAKeys.fromKeyFiles("/publicKey.txt", "/privateKey.txt");
	}

	@Before
	public void setUp() {
		originalSystemProperties = System.getProperties();
		cut = JwtGenerator.getInstance(XSUAA, DEFAULT_CLIENT_ID).withPrivateKey(keys.getPrivate());
	}

	@After
	public void tearDown() {
		System.setProperties(originalSystemProperties);
	}

	@Test
	public void createToken_isNotNull() {
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.getClaimAsStringList(TokenClaims.AUDIENCE)).contains(DEFAULT_CLIENT_ID);
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(DEFAULT_CLIENT_ID);
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
	}

	@Test
	public void createIasToken_isNotNull() {
		cut = JwtGenerator.getInstance(IAS, "T000310")
				.withClaimValue("sub", "P176945")
				.withClaimValue("scope", "john.doe")
				.withClaimValue("iss", "https://application.myauth.com")
				.withClaimValue("first_name", "john")
				.withClaimValue("last_name", "doe")
				.withClaimValue("email", "john.doe@email.org")
				.withPrivateKey(keys.getPrivate());
		Token token = cut.createToken();

		assertThat(token).isNotNull();
		assertThat(token.getClaimAsString(TokenClaims.AUDIENCE)).isEqualTo("T000310");
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo("T000310");
		assertThat(token.getExpiration()).isEqualTo(JwtGenerator.NO_EXPIRE_DATE);
		String encodedModulusN = Base64.getUrlEncoder()
				.encodeToString(((RSAPublicKeyImpl) keys.getPublic()).getModulus().toByteArray());
		assertThat(encodedModulusN).startsWith("AJtUGmczI7RHx3");
	}

	@Test
	public void createToken_withoutPrivateKey_throwsException() {
		assertThatThrownBy(() -> JwtGenerator.getInstance(IAS, "T00001234").createToken())
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	public void withPrivateKey_usesPrivateKey() throws Exception {
		SignatureCalculator signatureCalculator = Mockito.mock(SignatureCalculator.class);

		when(signatureCalculator.calculateSignature(any(), any(), any())).thenReturn("sig".getBytes());

		JwtGenerator.getInstance(IAS, signatureCalculator, "T00001234").withPrivateKey(keys.getPrivate()).createToken();

		verify(signatureCalculator, times(1)).calculateSignature(eq(keys.getPrivate()), any(), any());
	}

	@Test
	public void withClaim_containsClaim() {
		String email = "john.doe@mail.de";

		Token token = cut
				.withClaimValue(TokenClaims.EMAIL, email)
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.EMAIL)).isEqualTo(email);
	}

	@Test
	public void withClaimClientId_overwritesClaim() {
		String clientId = "myClientId";

		Token token = cut
				.withClaimValue(TokenClaims.XSUAA.CLIENT_ID, clientId)
				.createToken();

		assertThat(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).isEqualTo(clientId);
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
	public void withLocalScopes_withoutAppId_throwsException() {
		assertThatThrownBy(() -> cut.withLocalScopes("Read").createToken())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("appId has not been set!");
	}

	@Test
	public void withScopes_serviceIsIAS_throwsUnsupportedOperationException() {
		cut = JwtGenerator.getInstance(IAS, "T00001234").withPrivateKey(keys.getPrivate());
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
	public void withSignatureAlgorithm_notSupported_throwsUnsupportedOperationException() {
		assertThatThrownBy(() -> cut.withClaimValues(TokenClaims.AUDIENCE, "app2", "app3"))
				.isInstanceOf(UnsupportedOperationException.class);
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
	public void loadClaimsFromFile_doesNotContainValidJson_throwsException() throws IOException {
		File emptyFile = temporaryFolder.newFile("empty");
		String temporaryFolderName = emptyFile.getParentFile().getName();
		String resourcePath = "/" + temporaryFolderName + "/empty";

		assertThatThrownBy(() -> cut.withClaimsFromFile(resourcePath).createToken())
				.isInstanceOf(JsonParsingException.class);
	}

	@Test
	public void loadClaimsFromFile_containsStringClaims() throws IOException {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getClaimAsString(TokenClaims.EMAIL)).isEqualTo("test@uaa.org");
		assertThat(token.getClaimAsString(TokenClaims.XSUAA.GRANT_TYPE))
				.isEqualTo("urn:ietf:params:oauth:grant-type:saml2-bearer");
	}

	@Test
	public void loadClaimsFromFile_containsExpirationClaim() throws IOException {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getExpiration()).isEqualTo(Instant.ofEpochSecond(1542416800));
	}

	@Test
	public void loadClaimsFromFile_containsJsonObjectClaims() throws IOException {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		JsonObject externalAttributes = token.getClaimAsJsonObject("ext_attr");

		assertThat(externalAttributes).isNotNull();
		assertThat(externalAttributes.getAsString("enhancer")).isEqualTo("XSUAA");
		assertThat(externalAttributes.getAsList("acl", String.class)).containsExactly("app1!t23");
	}

	@Test
	public void loadClaimsFromFile_containsListClaims() throws IOException {
		final Token token = cut.withClaimsFromFile("/claims.json").createToken();

		assertThat(token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES))
				.containsExactly("openid", "testScope", "testApp.localScope");
		assertThat(token.getClaimAsStringList("empty_list")).isEmpty();
	}

	@Test
	public void createToken_signatureCalculation_NoSuchAlgorithmExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new NoSuchAlgorithmException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_SignatureExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new SignatureException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_signatureCalculation_InvalidKeyExceptionTurnedIntoRuntimeException() {
		cut = JwtGenerator.getInstance(XSUAA, (key, alg, data) -> {
			throw new InvalidKeyException();
		}, "sb-client!1234").withPrivateKey(keys.getPrivate());
		assertThatThrownBy(() -> cut.createToken()).isInstanceOf(RuntimeException.class);
	}

	@Test
	public void createToken_tokenIsValid() throws IOException {
		System.setProperty("VCAP_SERVICES", IOUtils
				.resourceToString("/vcap.json", StandardCharsets.UTF_8));
		OAuth2ServiceConfiguration configuration = Environments.getCurrent().getXsuaaConfiguration();

		OAuth2TokenKeyService tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				.withOAuth2TokenKeyService(tokenKeyServiceMock)
				.build();

		Token token = cut
				.withHeaderParameter(TokenHeader.JWKS_URL, "http://auth.com/token_keys")
				.withExpiration(JwtGenerator.NO_EXPIRE_DATE)
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

	@Test
	public void createToken_discoverOidcJwksEndpoint_tokenIsValid() throws Exception {
		String clientId = "T000310";
		String url = "https://app.auth.com";
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(IAS)
				.withUrl(url)
				.withClientId(clientId)
				.build();

		OAuth2TokenKeyService tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenReturn(IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8));
		OAuth2ServiceEndpointsProvider endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(URI.create("http://auth.com/token_keys"));
		OidcConfigurationService oidcConfigServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);

		CombiningValidator<Token> tokenValidator = JwtValidatorBuilder.getInstance(configuration)
				.withOAuth2TokenKeyService(tokenKeyServiceMock)
				.withOidcConfigurationService(oidcConfigServiceMock)
				.build();

		Token token = JwtGenerator.getInstance(Service.IAS, clientId)
				.withClaimValue(TokenClaims.ISSUER, url)
				.withPrivateKey(keys.getPrivate())
				.withExpiration(JwtGenerator.NO_EXPIRE_DATE)
				.createToken();

		ValidationResult result = tokenValidator.validate(token);
		assertThat(result.isValid()).isTrue();
	}

}
