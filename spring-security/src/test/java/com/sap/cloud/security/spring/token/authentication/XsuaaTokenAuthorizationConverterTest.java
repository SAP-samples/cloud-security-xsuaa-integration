/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.token.authentication;

import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.spring.token.authentication.HybridJwtDecoder;
import com.sap.cloud.security.spring.token.authentication.XsuaaTokenAuthorizationConverter;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

import static com.sap.cloud.security.config.Service.XSUAA;
import static org.junit.jupiter.api.Assertions.*;

class XsuaaTokenAuthorizationConverterTest {
	String xsAppName = "my-app-name!400";
	JwtGenerator jwtGenerator = JwtGenerator.getInstance(XSUAA, "theClientId").withAppId(xsAppName);
	XsuaaTokenAuthorizationConverter cut = new XsuaaTokenAuthorizationConverter(xsAppName);
	String scopeAdmin = xsAppName + "." + "Admin";
	String scopeRead = xsAppName + "." + "Read";
	String scopeOther = "other-app!234" + "." + "Other";

	@Test
	void convert() {
		jwtGenerator.withScopes(scopeAdmin, scopeOther, scopeRead);
		Jwt jwt = HybridJwtDecoder.parseJwt(jwtGenerator.createToken());

		AbstractAuthenticationToken token = cut.convert(jwt);

		assertEquals(2, token.getAuthorities().size());
		assertTrue(token.getAuthorities().contains(new SimpleGrantedAuthority("Admin")));
		assertTrue(token.getAuthorities().contains(new SimpleGrantedAuthority("Read")));
	}

	@Test
	void localScopeAuthorities() {
		jwtGenerator.withScopes(scopeAdmin, scopeOther, scopeRead);
		Jwt jwt = HybridJwtDecoder.parseJwt(jwtGenerator.createToken());

		Collection<GrantedAuthority> grantedAuthorities = cut.localScopeAuthorities(jwt);

		assertEquals(2, grantedAuthorities.size());
		assertTrue(grantedAuthorities.contains(new SimpleGrantedAuthority("Admin")));
		assertTrue(grantedAuthorities.contains(new SimpleGrantedAuthority("Read")));
	}
}