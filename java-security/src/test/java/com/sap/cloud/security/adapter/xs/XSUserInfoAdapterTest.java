package com.sap.cloud.security.adapter.xs;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.tokenflows.ClientCredentialsTokenFlow;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.UserTokenFlow;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import com.sap.xsa.security.container.XSUserInfoException;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;

import static com.sap.cloud.security.adapter.xs.XSUserInfoAdapter.*;
import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.IDENTITY_ZONE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.TRUSTED_CLIENT_ID_SUFFIX;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

public class XSUserInfoAdapterTest {

	private static final String TEST_APP_ID = "testApp";
	private final XsuaaToken token;
	private XSUserInfoAdapter cut;
	private XsuaaToken emptyToken;

	public XSUserInfoAdapterTest() throws IOException {
		emptyToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaEmptyToken.txt", UTF_8));
		token = new XsuaaToken(IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", UTF_8));
	}

	@Before
	public void setUp() throws XSUserInfoException {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId("sb-clone1!b5|LR-master!b5")
				.withProperty(CFConstants.XSUAA.APP_ID, "brokerplanmasterapp!b123")
				.withProperty(IDENTITY_ZONE, "paas")
				.build();
		cut = new XSUserInfoAdapter(token.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID)), configuration);
	}

	@Test
	public void constructors() throws XSUserInfoException {
		assertThat(new XSUserInfoAdapter((Object) token).getLogonName()).isEqualTo("TestUser");
		assertThat(new XSUserInfoAdapter((Token) token).getLogonName()).isEqualTo("TestUser");
		assertThat(new XSUserInfoAdapter((AccessToken) token).getLogonName()).isEqualTo("TestUser");
		assertThatThrownBy(() -> new XSUserInfoAdapter(null)).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("null")
				.hasMessageContaining("instance of AccessToken");
		assertThatThrownBy(() -> new XSUserInfoAdapter("Tester")).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("String")
				.hasMessageContaining("instance of AccessToken");
	}

	@Test
	public void testGetLogonName() throws XSUserInfoException {
		assertThat(cut.getLogonName()).isEqualTo("TestUser");
	}

	@Test
	public void testGetLogonName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getLogonName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getLogonName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetGivenName() throws XSUserInfoException {
		assertThat(cut.getGivenName()).isEqualTo("TestUser");
	}

	@Test
	public void testGetGivenName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getGivenName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getGivenName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetFamilyName() throws XSUserInfoException {
		assertThat(cut.getFamilyName()).isEqualTo("unknown.org");
	}

	@Test
	public void testGetFamilyName_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getFamilyName()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getFamilyName")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetIdentityZone() throws XSUserInfoException {
		assertThat(cut.getIdentityZone()).isEqualTo("paas");
	}

	@Test
	public void testGetSubdomain() throws XSUserInfoException {
		assertThat(cut.getSubdomain()).isEqualTo("paas");
	}

	@Test
	public void testGetClientId() throws XSUserInfoException {
		assertThat(cut.getClientId()).isEqualTo("sb-clone1!b5|LR-master!b5");
	}

	@Test
	public void testGetJsonValue() throws XSUserInfoException {
		assertThat(cut.getJsonValue("cid")).isEqualTo("sb-clone1!b5|LR-master!b5");
	}

	@Test
	public void testGetEmail() throws XSUserInfoException {
		assertThat(cut.getEmail()).isEqualTo("TestUser@uaa.org");
	}

	@Test
	public void testGetEmail_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getEmail()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getEmail")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetAppToken() throws IOException {
		assertThat(cut.getAppToken()).isEqualTo(IOUtils.resourceToString("/xsuaaUserInfoAdapterToken.txt", UTF_8));
	}

	@Test
	public void getToken_namespaceNotSystem_throwsException() {
		assertThatThrownBy(() -> cut.getToken("any", "any")).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	public void testGetDBToken() throws XSUserInfoException {
		assertThat(cut.getDBToken()).isEqualTo(cut.getAppToken());
	}

	@Test
	public void testGetDBToken_onEmptyToken_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(emptyToken);

		assertThatThrownBy(() -> cut.getDBToken()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getHdbToken()).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	public void testGetHdbToken() throws XSUserInfoException {
		assertThat(cut.getHdbToken()).isEqualTo(cut.getAppToken());
	}

	@Test
	public void getToken_fallbackToTokenValue() throws XSUserInfoException {
		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo(token.getTokenValue());
	}

	@Test
	public void getToken_fromExternalContext() throws XSUserInfoException {
		String internalToken = "token";
		JsonObject externalContextMock = mock(JsonObject.class);
		when(externalContextMock.getAsString(HDB_NAMEDUSER_SAML)).thenReturn(internalToken);
		XsuaaToken mockToken = createMockToken(externalContextMock);

		cut = new XSUserInfoAdapter(mockToken);

		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo(internalToken);
	}

	@Test
	public void getToken_fromHDBNamedUserSaml() throws XSUserInfoException {
		String internalToken = "token";
		XsuaaToken mockToken = createMockToken();
		when(mockToken.getClaimAsString(HDB_NAMEDUSER_SAML)).thenReturn(internalToken);
		when(mockToken.getClaimAsJsonObject(XS_USER_ATTRIBUTES)).thenReturn(mock(JsonObject.class));

		cut = spy(new XSUserInfoAdapter(mockToken));
		doReturn(false).when(cut).isInForeignMode();

		assertThat(cut.getToken(XSUserInfoAdapter.SYSTEM, XSUserInfoAdapter.HDB)).isEqualTo(internalToken);
	}

	@Test
	public void testGetAttribute() throws XSUserInfoException {
		String[] attribute = cut.getAttribute("usrAttr");
		assertThat(attribute).contains("test");
	}

	@Test
	public void testGetAttribute_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getAttribute("any")).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getAttribute")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testHasAttributes_true() throws XSUserInfoException {
		assertThat(cut.hasAttributes()).isTrue();
	}

	@Test
	public void testHasAttributes_false() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(emptyToken);
		assertThat(cut.hasAttributes()).isFalse();
	}

	@Test
	public void testHasAttributes_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.hasAttributes()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("hasAttributes")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void testGetSystemAttribute() throws XSUserInfoException {
		String[] systemAttributes = cut.getSystemAttribute("xs.saml.groups");
		assertThat(systemAttributes).contains("g1");
	}

	@Test
	public void testCheckScope() throws XSUserInfoException {
		assertThat(cut.checkScope("testScope")).isTrue();
	}

	@Test
	public void testCheckLocalScope() throws XSUserInfoException {
		assertThat(cut.checkLocalScope("localScope")).isTrue();
	}

	@Test
	public void testCheckLocalScope_appNameNull_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(token.withScopeConverter(null));
		assertThatThrownBy(() -> cut.checkLocalScope("localScope")).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	public void testGetAdditionalAuthAttribute() throws XSUserInfoException {
		assertThat(cut.getAdditionalAuthAttribute("external_id")).isEqualTo("abcd1234");
	}

	@Test
	public void testGetCloneServiceInstanceId() throws XSUserInfoException {
		assertThat(cut.getCloneServiceInstanceId()).isEqualTo("brokerCloneServiceInstanceId");
	}

	@Test
	public void testGetGrantType() throws XSUserInfoException {
		assertThat(cut.getGrantType()).isEqualTo("urn:ietf:params:oauth:grant-type:saml2-bearer");
	}

	@Test
	public void isForeignModeIsTrue_whenConfigurationIsNotAvailable() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(token);
		assertThat(cut.isInForeignMode()).isTrue();
	}

	@Test
	public void testGetSubaccountId() throws XSUserInfoException {
		assertThat(cut.getSubaccountId()).isEqualTo("paas");
	}

	@Test
	public void testGetSubaccountIdFromSystemAttributes() throws XSUserInfoException {
		String token = "eyJqa3UiOiJodHRwOi8vbG9jYWxob3N0Iiwia2lkIjoiZGVmYXVsdC1raWQiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsic2ItY2xpZW50SWQhdDA4MTUiXSwiZXh0X2F0dHIiOnsiZW5oYW5jZXIiOiJYU1VBQSIsInpkbiI6InVhYSIsImFjbCI6WyJhcHAxIXQyMyJdLCJzZXJ2aWNlaW5zdGFuY2VpZCI6ImJyb2tlckNsb25lU2VydmljZUluc3RhbmNlSWQifSwiYXpfYXR0ciI6eyJleHRlcm5hbF9pZCI6ImFiY2QxMjM0In0sImdyYW50X3R5cGUiOiJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6Z3JhbnQtdHlwZTpzYW1sMi1iZWFyZXIiLCJzY29wZSI6WyJvcGVuaWQiLCJ0ZXN0U2NvcGUiLCJ0ZXN0QXBwLmxvY2FsU2NvcGUiXSwiZW1wdHlfbGlzdCI6W10sInhzLnN5c3RlbS5hdHRyaWJ1dGVzIjp7InN1YmFjY291bnRpZCI6InRlc3Qtc3ViYWNjb3VudCJ9LCJleHAiOjE1NDI0MTY4MDAsImVtYWlsIjoidGVzdEB1YWEub3JnIiwiY2lkIjoic2ItY2xpZW50SWQhdDA4MTUifQ.dbCiJFDooPvJ0Sla3pnVXn5exNcVw7dKPgaDF3w_mFS6HqkzhxSwujy0PHtolHlaD1PztZ-6Lyi_eWqlIP3QjIxXKAkf2b3BcAF6WDRX3p5h8Noql9UDoNvYSNImdQcDWN2cZ5q2TzIv2X46HwW0cFP86oKFykALvp_CHlW1GKeJ8VdSWHoMJlOsdoKrLe68HKkIot1yjLsVr9i5LlsQm1EwR_GijLZeDHQNnYL2i_XWOhz3o6bjlcXicdhUaXEBp9CRvb0zucSYbTWJB5tV4e4i0GShXioX6qJG5NOgBZqsigUEaWACfO7Cmdzbr7AsVTlxb_mww9fF7wSAzrW1zA";
		cut = new XSUserInfoAdapter(new XsuaaToken(token));
		assertThat(cut.getSubaccountId()).isEqualTo("test-subaccount");
	}

	@Test
	public void testGetOrigin() throws XSUserInfoException {
		assertThat(cut.getOrigin()).isEqualTo("useridp");
	}

	@Test
	public void requestTokenForClient() throws TokenFlowException {
		String clientId = "theClientId";
		String clientSecret = "theClientSecret";
		String uaaBaseUrl = "http://oauth.base.url/oauth/token";

		XsuaaTokenFlows xsuaaTokenFlowsMock = Mockito.mock(XsuaaTokenFlows.class);
		doReturn(clientCredentialsTokenFlowMock()).when(xsuaaTokenFlowsMock).clientCredentialsTokenFlow();
		cut = createComponentUnderTestSpy();
		doReturn(xsuaaTokenFlowsMock).when(cut).getXsuaaTokenFlows(anyString(), any(ClientCredentials.class));

		cut.requestTokenForClient(clientId, clientSecret, uaaBaseUrl);

		verify(cut, times(1)).getXsuaaTokenFlows(eq(uaaBaseUrl), eq(new ClientCredentials(clientId, clientSecret)));
		verify(xsuaaTokenFlowsMock, times(1)).clientCredentialsTokenFlow();
	}

	@Test
	public void requestTokenForUser() throws TokenFlowException {
		String clientId = "theClientId";
		String clientSecret = "theClientSecret";
		String uaaBaseUrl = "http://oauth.base.url/oauth/token";
		String token = "token";

		XsuaaTokenFlows xsuaaTokenFlowsMock = Mockito.mock(XsuaaTokenFlows.class);
		UserTokenFlow userTokenFlowMock = userTokenFlowMock();
		doReturn(userTokenFlowMock).when(xsuaaTokenFlowsMock).userTokenFlow();
		cut = createComponentUnderTestSpy();
		doReturn(xsuaaTokenFlowsMock).when(cut).getXsuaaTokenFlows(anyString(), any(ClientCredentials.class));
		doReturn(token).when(cut).getAppToken();

		cut.requestTokenForUser(clientId, clientSecret, uaaBaseUrl);

		verify(cut, times(1)).getXsuaaTokenFlows(eq(uaaBaseUrl), eq(new ClientCredentials(clientId, clientSecret)));
		verify(cut, times(1)).getAppToken();
		verify(userTokenFlowMock, times(1)).token(token);
		verify(xsuaaTokenFlowsMock, times(1)).userTokenFlow();
	}

	@Test
	public void testGetOrigin_grantTypeClientCredentials_throwsException() throws XSUserInfoException {
		cut = new XSUserInfoAdapter(createMockToken(GrantType.CLIENT_CREDENTIALS));

		assertThatThrownBy(() -> cut.getOrigin()).isInstanceOf(XSUserInfoException.class)
				.hasMessageContaining("getOrigin")
				.hasMessageContaining(GrantType.CLIENT_CREDENTIALS.toString());
	}

	@Test
	public void accessAttributes_doNotExist_throwsException() throws IOException, XSUserInfoException {
		String nonExistingAttribute = "doesNotExist";
		cut = new XSUserInfoAdapter(emptyToken.withScopeConverter(new XsuaaScopeConverter(TEST_APP_ID)));

		assertThatThrownBy(() -> cut.getGrantType()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getLogonName()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getFamilyName()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getIdentityZone()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getDBToken()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getCloneServiceInstanceId()).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getGrantType()).isInstanceOf(XSUserInfoException.class);

		assertThatThrownBy(() -> cut.getJsonValue(nonExistingAttribute)).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getAttribute(nonExistingAttribute)).isInstanceOf(XSUserInfoException.class);
		assertThatThrownBy(() -> cut.getSystemAttribute(nonExistingAttribute)).isInstanceOf(XSUserInfoException.class);
	}

	@Test
	public void getHdbToken_AuthCodeToken_NoAttributes() throws XSUserInfoException, IOException {
		XsuaaToken token = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaXsaAccessTokenRSA256_signedWithVerificationKey.txt", UTF_8));
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId("sb-java-hello-world!i1")
				.withProperty(CFConstants.XSUAA.APP_ID, "java-hello-world!i1")
				.withProperty(IDENTITY_ZONE, "uaa")
				.withProperty("identityzoneid", "uaa")
				.build();

		cut = new XSUserInfoAdapter(token, configuration);

		assertThat(cut.getHdbToken()).isNotNull();
		assertThat(cut.getHdbToken()).startsWith("eyJhbGciOiAiUlMyNTYiLCJ0eXAiOiAiS");
	}

	@Test
	public void getHdbToken_AudCodeToken_WithAttributes() throws XSUserInfoException {
		XsuaaToken token = mock(XsuaaToken.class);
		String mockTokenValue = "mock token value";

		when(token.getTokenValue()).thenReturn(mockTokenValue);
		when(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).thenReturn("sb-margin-assurance-ui!i1");
		when(token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)).thenReturn("uaa");
		when(token.getGrantType()).thenReturn(GrantType.AUTHORIZATION_CODE);

		JsonObject xsUserAttributes = mock(JsonObject.class);
		when(xsUserAttributes.isEmpty()).thenReturn(false);
		when(token.getClaimAsJsonObject(XS_USER_ATTRIBUTES)).thenReturn(xsUserAttributes);

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId("sb-margin-assurance-ui!i1")
				.withProperty(CFConstants.XSUAA.APP_ID, "margin-assurance-ui!i1")
				.withProperty(IDENTITY_ZONE, "uaa")
				.withProperty("identityzoneid", "uaa")
				.build();

		cut = new XSUserInfoAdapter(token, configuration);

		assertThat(cut.getHdbToken()).isNotNull();
		assertThat(cut.getHdbToken()).isEqualTo(mockTokenValue);
	}

	@Test
	public void isForeignModeFalse_whenTrustedClientIdSuffixMatches() throws XSUserInfoException {
		String tokenClientId = "sb-clone1!b22|brokerplanmasterapp!b123"; // cid
		String configurationAppId = "brokerplanmasterapp!b123";
		XsuaaToken token = mock(XsuaaToken.class);
		when(token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)).thenReturn(tokenClientId);
		when(token.getClaimAsString(TokenClaims.XSUAA.ZONE_ID)).thenReturn("otherIdentityZone");

		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(CFConstants.CLIENT_ID, tokenClientId)
				.withProperty(CFConstants.XSUAA.APP_ID, configurationAppId)
				.withProperty(IDENTITY_ZONE, "uaa")
				.withProperty(TRUSTED_CLIENT_ID_SUFFIX, "|brokerplanmasterapp!b123")
				.build();

		cut = new XSUserInfoAdapter(token, configuration);

		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	public void isForeignModeFalse_WhenIdentityZoneDoesNotMatchButCliendIdIsApplicationPlan()
			throws XSUserInfoException {
		String tokenClientId = "sb-application!t0123"; // cid
		String identityZone = "brokerplanmasterapp!b123"; // ext_attr -> zdn
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(IDENTITY_ZONE, identityZone)
				.build();

		cut = createComponentUnderTestSpy(configuration);
		doReturn(tokenClientId).when(cut).getClientId();
		doReturn("otherIdentityZone").when(cut).getIdentityZone();

		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	public void isForeignModeFalse_WhenIdentityZoneDoesNotMatchButCliendIdIsBrokerPlan()
			throws XSUserInfoException {
		String tokenClientId = "sb-application!b0123"; // cid
		String identityZone = "brokerplanmasterapp!b123"; // ext_attr -> zdn
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(IDENTITY_ZONE, identityZone)
				.build();

		cut = createComponentUnderTestSpy(configuration);
		doReturn(tokenClientId).when(cut).getClientId();
		doReturn("otherIdentityZone").when(cut).getIdentityZone();

		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	public void isForeignModeFalse_WhenClientIdAndIdentityZonesMatch() throws XSUserInfoException {
		String tokenClientId = "sb-application"; // cid
		String identityZone = "brokerplanmasterapp!b123"; // ext_attr -> zdn
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withClientId(tokenClientId)
				.withProperty(IDENTITY_ZONE, identityZone)
				.build();

		cut = createComponentUnderTestSpy(configuration);
		doReturn(tokenClientId).when(cut).getClientId();
		doReturn(identityZone).when(cut).getIdentityZone();

		assertThat(cut.isInForeignMode()).isFalse();
	}

	@Test
	public void isForeignModeTrue_whenClientIdDoesNotMatchIdentityZone() throws XSUserInfoException {
		OAuth2ServiceConfiguration configuration = OAuth2ServiceConfigurationBuilder.forService(Service.XSUAA)
				.withProperty(CFConstants.XSUAA.APP_ID, "sb-application")
				.build();

		cut = createComponentUnderTestSpy(configuration);
		doReturn("sb-application!t0123").when(cut).getClientId();
		doReturn("otherIdentityZone").when(cut).getIdentityZone();

		assertThat(cut.isInForeignMode()).isTrue();
	}

	@Test
	public void isForeignModeTrue_whenClientIdIsMissing() throws XSUserInfoException {
		cut = createComponentUnderTestSpy();

		doReturn("brokerplanmasterapp!b123").when(cut).getIdentityZone();
		doThrow(new XSUserInfoException("")).when(cut).getClientId();

		assertThat(cut.isInForeignMode()).isTrue();
	}

	@Test
	public void isForeignModeTrue_whenIdentityZoneIsMissing() throws XSUserInfoException {
		cut = createComponentUnderTestSpy();

		doReturn("sb-application!t0123").when(cut).getClientId();
		doThrow(new XSUserInfoException("")).when(cut).getIdentityZone();

		assertThat(cut.isInForeignMode()).isTrue();
	}

	private XSUserInfoAdapter createComponentUnderTestSpy() throws XSUserInfoException {
		return spy(new XSUserInfoAdapter(mock(XsuaaToken.class), mock(OAuth2ServiceConfiguration.class)));
	}

	private XSUserInfoAdapter createComponentUnderTestSpy(OAuth2ServiceConfiguration configuration)
			throws XSUserInfoException {
		return spy(
				new XSUserInfoAdapter(Mockito.mock(XsuaaToken.class), configuration));
	}

	private XsuaaToken createMockToken(GrantType grantType) {
		XsuaaToken mockToken = mock(XsuaaToken.class);
		when(mockToken.getGrantType()).thenReturn(grantType);
		return mockToken;
	}

	private XsuaaToken createMockToken() {
		return createMockToken(GrantType.SAML2_BEARER);
	}

	private XsuaaToken createMockToken(JsonObject externalContext) {
		final XsuaaToken mockToken = createMockToken();
		when(mockToken.hasClaim(EXTERNAL_CONTEXT)).thenReturn(true);
		when(mockToken.getClaimAsJsonObject(EXTERNAL_CONTEXT)).thenReturn(externalContext);
		return mockToken;
	}

	private UserTokenFlow userTokenFlowMock() throws TokenFlowException {
		UserTokenFlow userTokenFlowMock = mock(UserTokenFlow.class);
		when(userTokenFlowMock.subdomain(any())).thenReturn(userTokenFlowMock);
		when(userTokenFlowMock.attributes(any())).thenReturn(userTokenFlowMock);
		when(userTokenFlowMock.token(any())).thenReturn(userTokenFlowMock);
		when(userTokenFlowMock.execute()).thenReturn(Mockito.mock(OAuth2TokenResponse.class));
		return userTokenFlowMock;
	}

	private ClientCredentialsTokenFlow clientCredentialsTokenFlowMock() throws TokenFlowException {
		ClientCredentialsTokenFlow clientCredentialsTokenFlowMock = mock(ClientCredentialsTokenFlow.class);
		when(clientCredentialsTokenFlowMock.subdomain(any())).thenReturn(clientCredentialsTokenFlowMock);
		when(clientCredentialsTokenFlowMock.attributes(any())).thenReturn(clientCredentialsTokenFlowMock);
		when(clientCredentialsTokenFlowMock.execute()).thenReturn(Mockito.mock(OAuth2TokenResponse.class));
		return clientCredentialsTokenFlowMock;
	}
}