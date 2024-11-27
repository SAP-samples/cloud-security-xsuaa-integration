/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;

import static com.sap.cloud.security.token.TokenClaims.USER_NAME;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class XsuaaTokenTest {

	private final XsuaaToken clientCredentialsToken;
	private final XsuaaToken userToken;

	public XsuaaTokenTest() throws IOException {
		clientCredentialsToken = new XsuaaToken(
				IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", UTF_8));
		userToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8));
	}

	@Test
	public void constructor_raiseIllegalArgumentExceptions() {
		assertThatThrownBy(() -> new XsuaaToken("")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("jwtToken must not be null / empty");

		assertThatThrownBy(() -> new XsuaaToken("abc")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("JWT token does not consist of 'header'.'payload'.'signature'.");
	}

	@Test
	public void getScopes() {
		assertThat(clientCredentialsToken.getScopes()).containsExactly("ROLE_SERVICEBROKER", "uaa.resource");
	}

	@Test
	public void hasScope_scopeExists_isTrue() {
		assertThat(clientCredentialsToken.hasScope("ROLE_SERVICEBROKER")).isTrue();
		assertThat(clientCredentialsToken.hasScope("uaa.resource")).isTrue();
	}

	@Test
	public void hasScope_scopeDoesNotExist_isFalse() {
		assertThat(clientCredentialsToken.hasScope("scopeDoesNotExist")).isFalse();
	}

	@Test
	public void hasLocalScope() {
		clientCredentialsToken.withScopeConverter(new XsuaaScopeConverter("uaa"));
		assertThat(clientCredentialsToken.hasScope("uaa.resource")).isTrue();
		assertThat(clientCredentialsToken.hasLocalScope("resource")).isTrue();
	}

	@Test
	public void getUserPrincipal() {
		assertThat(userToken.getClaimAsString(TokenClaims.USER_NAME)).isEqualTo("testUser");
		assertThat(userToken.getClaimAsString(TokenClaims.XSUAA.ORIGIN)).isEqualTo("userIdp");
		assertThat(userToken.getPrincipal()).isNotNull();
		assertThat(userToken.getPrincipal().getName()).isEqualTo("user/userIdp/testUser");
	}

	@Test
	public void getClientPrincipal() {
		assertThat(clientCredentialsToken.getClientId()).isEqualTo("sap_osb");
		assertThat(clientCredentialsToken.getPrincipal()).isNotNull();
		assertThat(clientCredentialsToken.getPrincipal().getName()).isEqualTo("client/sap_osb");
	}

	@Test
	public void getPrincipalGrantTypeIsNull() {
		XsuaaToken tokenMock = Mockito.mock(XsuaaToken.class);
		Mockito.when(tokenMock.getGrantType()).thenReturn(null);
		Mockito.when(tokenMock.getClaimAsString(ORIGIN)).thenReturn("sap");
		Mockito.when(tokenMock.getClaimAsString(USER_NAME)).thenReturn("user");
		Mockito.when(tokenMock.getPrincipal()).thenCallRealMethod();
		Mockito.when(tokenMock.createPrincipalByName(anyString())).thenCallRealMethod();

		assertThat(tokenMock.getPrincipal()).isNotNull();
		assertThat(tokenMock.getPrincipal().getName()).isEqualTo("user/sap/user");
	}

	@Test
	public void getGrantType() {
		assertThat(clientCredentialsToken.getGrantType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
		assertThat(userToken.getGrantType()).isEqualTo(GrantType.JWT_BEARER);
	}

	@Test
	public void getService() {
		assertThat(userToken.getService()).isEqualTo(Service.XSUAA);
	}

	@Test
	public void getUniquePrincipalName() {
		assertThat(XsuaaToken.getUniquePrincipalName("origin", "user"))
				.isEqualTo("user/origin/user");
	}

	@Test
	public void getUniquePrincipalName_cannotBeCreated_returnsNull() {
		assertThat(XsuaaToken.getUniquePrincipalName("origin/", "user")).isNull();
		assertThat(XsuaaToken.getUniquePrincipalName("origin", "")).isNull();
		assertThat(XsuaaToken.getUniquePrincipalName("", "user")).isNull();
		assertThat(XsuaaToken.getUniquePrincipalName(null, "user")).isNull();
		assertThat(XsuaaToken.getUniquePrincipalName("origin", null)).isNull();
	}

	@Test
	public void getPrincipalShouldBeEqualForSameUser() throws IOException {
		Token userToken2 = new XsuaaToken(IOUtils.resourceToString("/xsuaaJwtBearerTokenRSA256.txt", UTF_8));
		assertThat(userToken.getPrincipal()).isEqualTo(userToken2.getPrincipal());
	}

	@Test
	public void getAudiences() {
		assertThat(clientCredentialsToken.getAudiences()).containsExactlyInAnyOrder("uaa", "sap_osb");
	}

	@Test
	public void getSubdomain() {
		assertThat(clientCredentialsToken.getSubdomain()).isNull();
		assertThat(userToken.getSubdomain()).isEqualTo("theSubdomain");
	}

	@Test
	public void getSubdomainFromCCTokenWhithoutZdn() {
		assertThat(clientCredentialsToken.getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, EXTERNAL_ATTRIBUTE_ZDN))
				.isNull();
	}

	@Test
	public void getAttributeFromNotExistingClaim() {
		assertThat(clientCredentialsToken.getAttributeFromClaimAsString("not_existing", EXTERNAL_ATTRIBUTE_ZDN))
				.isNull();
	}

	@Test
	public void getNotExistingAttributeFromExistingClaim() {
		assertThat(clientCredentialsToken.getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, "notExisting")).isNull();
	}

	@Test
	public void getSubaccountId() {
		XsuaaToken userTokenWithSubaccountId = Mockito.spy(userToken);
		when(userTokenWithSubaccountId.getClaimAsJsonObject(EXTERNAL_ATTRIBUTE))
				.thenReturn(new DefaultJsonObject("{\"subaccountid\": \"abc123\"}"));

		assertThat(userTokenWithSubaccountId.getSubaccountId()).isEqualTo("abc123");
	}

	@Test
	public void getSubaccountId_noSubaccountId_fallsBackToZoneId() {
		assertThat(clientCredentialsToken.getSubaccountId()).isEqualTo("uaa");
	}

	@Test
	public void readCloneServiceInstanceId() {
		String authHeader = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHRfYXR0ciI6eyJ6ZG4iOiJ0ZXN0c3ViZG9tYWluIiwic2VydmljZWluc3RhbmNlaWQiOiJhYmNkMTIzNCJ9LCJ6aWQiOiJlMmY3ZmJkYi0wMzI2LTQwZTYtOTQwZi1kZmRkYWQwNTdmZjMiLCJncmFudF90eXBlIjoidXJuOmlldGY6cGFyYW1zOm9hdXRoOmdyYW50LXR5cGU6c2FtbDItYmVhcmVyIiwidXNlcl9uYW1lIjoidGVzdFVzZXIiLCJvcmlnaW4iOiJ1c2VySWRwIiwiZXhwIjo2OTc0MDMxNjAwLCJpYXQiOjE1OTM3ODQ2MDcsImVtYWlsIjoidGVzdFVzZXJAdGVzdC5vcmciLCJjaWQiOiJzYi1qYXZhLWhlbGxvLXdvcmxkIn0.yB_ALtO_shdJJkXeRSxKFRVghDmrxdnZ1-WssO_hQ9AAuaQX-rA6eMwuikjcWhkzWnjBzQg4LO8aLQhtUUIS60cpXZG_zP7y9iULCxQQt2vTMbVC0unHB2ytBf2GWbIq_WplfNwshZmbt2ETDClz87VBla-yG6rIZdAio4jZuLTQzJAVCMhJCkmhuMedzbrzGovpblT49UIbi3v4cxhBuoHhAZVfPEUX4-22BTcgFFVlOySvDn6xBVLVqBcjOl_JGjFcWPImj0BqdEuaQq2-A3_F_XKhQf_AK7rLF7kvaIZ2k3i-1GWapqLZsCed23Ihce5m-cedv3857YQPZxAHZw";
		XsuaaToken token = new XsuaaToken(authHeader);
		assertThat(token.getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, "serviceinstanceid"))
				.isEqualTo("abcd1234");
	}

	@Test
	public void getSubaccountId_noSubaccountIdAndFallback_toZoneId() {
		assertThat(userToken.getSubaccountId()).isEqualTo("the-zone-id");
	}

	@Test
	public void checkAppTidFallback() {
		XsuaaToken token = Mockito.mock(XsuaaToken.class);
		when(token.getZoneId()).thenCallRealMethod();
		when(token.getAppTid()).thenCallRealMethod();
		when(token.getClaimAsString(ZONE_ID)).thenReturn("zid");

		assertThat(token.getZoneId()).isEqualTo("zid");
		assertThat(token.getAppTid()).isEqualTo("zid");
	}

}
