/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.extractor.AuthenticationMethod;
import com.sap.cloud.security.xsuaa.extractor.DefaultAuthenticationInformationExtractor;
import com.sap.cloud.security.xsuaa.extractor.TokenBrokerResolver;
import com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.web.client.RestOperations;

import java.util.concurrent.TimeUnit;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Autowired
	RestOperations xsuaaMtlsRestOperations;

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		//enforce browser login popup with basic authentication
		BasicAuthenticationEntryPoint authEntryPoint = new BasicAuthenticationEntryPoint();
		authEntryPoint.setRealmName("spring-security-basic-auth");

		// @formatter:off
		http.authorizeRequests()
				.antMatchers("/hello-token").hasAuthority("Display")
				.antMatchers("/health").permitAll()
				.anyRequest().denyAll()
			.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and().exceptionHandling().authenticationEntryPoint(authEntryPoint).and()
				.oauth2ResourceServer()
				.bearerTokenResolver(getTokenBrokerResolver())
				.jwt()
				.jwtAuthenticationConverter(jwtAuthenticationConverter());

		// @formatter:on
	}

	BearerTokenResolver getTokenBrokerResolver() {
		Cache cache = new CaffeineCache("token",
				Caffeine.newBuilder()
						.expireAfterWrite(15, TimeUnit.MINUTES)
						.maximumSize(100).build(), false);

		return new TokenBrokerResolver(xsuaaServiceConfiguration, cache,
				new XsuaaOAuth2TokenService(xsuaaMtlsRestOperations),
				new DefaultAuthenticationInformationExtractor(AuthenticationMethod.BASIC));
	}


	@Bean
	Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration);
		converter.setLocalScopeAsAuthorities(true);
		return converter;
	}
}
