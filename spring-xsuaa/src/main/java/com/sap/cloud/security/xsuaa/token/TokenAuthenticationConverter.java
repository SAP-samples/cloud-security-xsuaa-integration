package com.sap.cloud.security.xsuaa.token;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

/**
 * Converter for xsuaa jwt token that stores authorization data like scopes
 * inside the token.
 */
public class TokenAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	protected String appId;
	protected boolean provideLocalScopesOnly;

	public TokenAuthenticationConverter(String appId) {
		this.appId = appId;
	}

	public TokenAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this.appId = xsuaaServiceConfiguration.getAppId();
		this.provideLocalScopesOnly = false;
	}

	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {
		return new AuthenticationToken(appId, jwt, extractAuthorities(jwt));
	}

	/**
	 * This method allows to overwrite the default behavior of the
	 * {@link Token#getAuthorities()} implementation.
	 *
	 * @param extractLocalScopesOnly
	 *            true when {@link Token#getAuthorities()} should only extract local
	 *            scopes. Local scopes means that non-application specific scopes
	 *            are filtered out and scopes are returned without appId prefix,
	 *            e.g. "Display".
	 */
	public void setLocalScopeAsAuthorities(boolean extractLocalScopesOnly) {
		this.provideLocalScopesOnly = extractLocalScopesOnly;
	}

	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		Collection<String> scopeAuthorities = getScopes(jwt);
		Collection<String> customAuthorities = getCustomAuthorities(new TokenImpl(jwt, appId));

		Stream<String> authorities = Stream.of(scopeAuthorities, customAuthorities).flatMap(Collection::stream);
		return authorities.map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	protected Collection<String> getCustomAuthorities(Token token) {
		return Collections.emptyList();
	}

	protected Collection<String> getScopes(Jwt jwt) {
		List<String> scopesList = jwt.getClaimAsStringList(Token.CLAIM_SCOPES);
		if (scopesList == null) {
			return Collections.emptyList();
		}
		if (provideLocalScopesOnly == true) {
			return scopesList.stream()
					.filter(scope -> scope.startsWith(appId + "."))
					.map(scope -> scope.replaceFirst(appId + ".", ""))
					.collect(Collectors.toList());
		} else {
			return scopesList.stream().collect(Collectors.toList());
		}

	}
}