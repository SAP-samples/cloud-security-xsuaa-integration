/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Internal class used to expose the {@link Token} implementation as the
 * standard Principal for Spring Security Jwt handling.
 *
 * @see TokenAuthenticationConverter
 * @see XsuaaToken
 */
public class AuthenticationToken extends JwtAuthenticationToken {
	private static final long serialVersionUID = -3779129534612771294L;

	private Token token;

	public AuthenticationToken(Jwt jwt, Collection<GrantedAuthority> authorities) {
		super(jwt, authorities);

		// Here is where the actual magic happens.
		// The Jwt is exchanged for another implementation.
		XsuaaToken xsuaaToken = new XsuaaToken(getToken());
		xsuaaToken.setAuthorities(this.getAuthorities());
		this.token = xsuaaToken;
	}

	@Override
	public Object getPrincipal() {
		return token;
	}

	@Override
	public String getName() {
		return token.getUsername();
	}
}
