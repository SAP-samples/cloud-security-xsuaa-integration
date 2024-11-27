/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.xsuaa.extractor.AuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.extractor.LocalAuthoritiesExtractor;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;

public class TokenAuthenticationConverterTest {
	private String xsAppName = "my-app-name!400";
	private TokenAuthenticationConverter tokenConverterDefault;
	private TokenAuthenticationConverter tokenConverterLocalScopesOnly;
	String scopeAdmin = xsAppName + "." + "Admin";
	String scopeRead = xsAppName + "." + "Read";
	String scopeOther = "other-app!234" + "." + "Other";

	@BeforeEach
	public void setup() {
		tokenConverterDefault = new TokenAuthenticationConverter(xsAppName);

		tokenConverterLocalScopesOnly = new TokenAuthenticationConverter(xsAppName);
		tokenConverterLocalScopesOnly.setLocalScopeAsAuthorities(true);
	}

	@Test
	public void extractAuthoritiesWithoutScopes() {
		Jwt jwt = new JwtGenerator().getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterDefault.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(0));
	}

	@Test
	public void extractAuthoritiesIgnoresForeignScopes() {
		Jwt jwt = new JwtGenerator().addScopes(scopeAdmin, scopeOther, scopeRead).getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterLocalScopesOnly.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(2));
		assertThat(authenticationToken.getAuthorities(), not(hasItem(new SimpleGrantedAuthority("Other"))));
	}

	@Test
	public void extractAuthoritiesWithScopes() {
		Jwt jwt = new JwtGenerator().addScopes(scopeAdmin, scopeRead, scopeOther).getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterDefault.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(3));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeRead)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeOther)));
	}

	@Test
	public void extractCustomAuthoritiesWithScopes() {
		TokenAuthenticationConverter tokenConverterCustom = new TokenAuthenticationConverter(
				new MyAuthoritiesExtractor(xsAppName, "cost-center",
						"country"));

		Jwt jwt = new JwtGenerator()
				.addScopes(scopeAdmin)
				.addAttribute("cost-center", new String[] { "0815" })
				.addAttribute("country", new String[] { "DE", "IL" })
				.getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterCustom.convert(jwt);
		assertThat(authenticationToken.getAuthorities().size(), is(4));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COST-CENTER=0815")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COUNTRY=DE")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("ATTR:COUNTRY=IL")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
	}

	@Test
	public void authoritiesHaveLocalScopesWithoutAppIdPrefix() {
		String scopeWithNamespace = xsAppName + ".iot.Delete";
		String scopeWithOtherAppId = "anyAppId!t200." + xsAppName + ".Delete";

		Jwt jwt = new JwtGenerator()
				.addScopes(xsAppName + "." + scopeAdmin, scopeRead, scopeWithNamespace, scopeWithOtherAppId)
				.getToken();

		AbstractAuthenticationToken authenticationToken = tokenConverterLocalScopesOnly.convert(jwt);

		assertThat(authenticationToken.getAuthorities().size(), is(3));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority(scopeAdmin)));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("iot.Delete")));
		assertThat(authenticationToken.getAuthorities(), hasItem(new SimpleGrantedAuthority("Read")));
	}

	@Test
	public void checkFollowingInstanceScope() {
		String scopeWithClientId = "7cf2e319-3a7d-4f99-8207-afdc8e8e6d64!b123|trustedclientid!b333.API_OVERVIEW";

		Jwt jwt = new JwtGenerator("sb-7cf2e319-3a7d-4f99-8207-afdc8e8e6d64!b123|trustedclientid!b333")
				.addScopes(xsAppName + "." + scopeAdmin, scopeRead, scopeWithClientId)
				.getToken();
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(
				new MyFollowingInstanceAuthoritiesExtractor());

		assertThat(converter.convert(jwt).getAuthorities().size(), is(1));
		assertThat(converter.convert(jwt).getAuthorities(), hasItem(new SimpleGrantedAuthority("API_OVERVIEW")));

	}

	private static class MyAuthoritiesExtractor implements AuthoritiesExtractor {
		private String[] xsUserAttributes;
		private AuthoritiesExtractor authoritiesExtractor;

		public MyAuthoritiesExtractor(String... xsUserAttributes) {
			authoritiesExtractor = new DefaultAuthoritiesExtractor();
			this.xsUserAttributes = xsUserAttributes;
		}

		@Override
		public Collection<GrantedAuthority> getAuthorities(XsuaaToken token) {
			Collection<GrantedAuthority> authorities = authoritiesExtractor.getAuthorities(token);
			authorities.addAll(getCustomAuthorities(token));
			return authorities;
		}

		private Collection<GrantedAuthority> getCustomAuthorities(Token token) {
			Set<GrantedAuthority> newAuthorities = new HashSet<>();
			for (String attribute : xsUserAttributes) {
				String[] xsUserAttributeValues = token.getXSUserAttribute(attribute);
				if (xsUserAttributeValues != null) {
					for (String xsUserAttributeValue : xsUserAttributeValues) {
						newAuthorities.add(new SimpleGrantedAuthority(
								getSidForAttributeValue(attribute, xsUserAttributeValue)));
					}
				}
			}
			return newAuthorities;
		}

		private static String getSidForAttributeValue(String attributeName, String attributeValue) {
			return "ATTR:" + attributeName.toUpperCase() + "=" + attributeValue;
		}

	}

	private static class MyFollowingInstanceAuthoritiesExtractor implements AuthoritiesExtractor {

		@Override
		public Collection<GrantedAuthority> getAuthorities(XsuaaToken token) {
			String appId = "";
			if (token.getClientId().startsWith("sb-")) {
				appId = token.getClientId().replaceFirst("sb-", "");
			}
			AuthoritiesExtractor authoritiesExtractor = new LocalAuthoritiesExtractor(appId);
			return authoritiesExtractor.getAuthorities(token);
		}

	}
}
