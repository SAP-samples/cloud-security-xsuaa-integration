/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security;

import com.sap.cloud.security.spring.config.IdentityServicesPropertySourceFactory;
import com.sap.cloud.security.spring.token.authentication.AuthenticationToken;
import com.sap.cloud.security.token.TokenClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Configuration
@EnableWebSecurity(debug = true) // TODO "debug" may include sensitive information. Do not use in a production system!
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@PropertySource(factory = IdentityServicesPropertySourceFactory.class, ignoreResourceNotFound = true, value = { "" })
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	Converter<Jwt, AbstractAuthenticationToken> authConverter;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
				.authorizeRequests()
				.antMatchers("/sayHello").hasAuthority("Read")
				.antMatchers("/*").authenticated()
				.anyRequest().denyAll()
			.and()
				.oauth2ResourceServer()
				.jwt()
				.jwtAuthenticationConverter(new MyCustomTokenAuthenticationConverter());
		// @formatter:on
	}

	/**
	 * Workaround until Cloud Authorization Service is globally available.
	 */
	class MyCustomTokenAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

		public AbstractAuthenticationToken convert(Jwt jwt) {
			if(jwt.hasClaim(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE)) {
				return authConverter.convert(jwt);
			}
			return new AuthenticationToken(jwt, deriveAuthoritiesFromGroup(jwt));
		}

		private Collection<GrantedAuthority> deriveAuthoritiesFromGroup(Jwt jwt) {
			Collection<GrantedAuthority> groupAuthorities = new ArrayList<>();
			if (jwt.hasClaim(TokenClaims.GROUPS)) {
				List<String> groups = jwt.getClaimAsStringList(TokenClaims.GROUPS);
				for (String group: groups) {
					groupAuthorities.add(new SimpleGrantedAuthority(group.replace("IASAUTHZ_", "")));
				}
			}
			return groupAuthorities;
		}
	}
}
