package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.Token;
import org.springframework.security.oauth2.jwt.Jwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Principal;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static com.sap.cloud.security.token.TokenClaims.*;

class IasToken implements Token {

	private Jwt decodedToken;

	public IasToken(Jwt jwt) {
		this.decodedToken = jwt;
	}

	@Nullable
	@Override
	public String getHeaderParameterAsString(@Nonnull String headerName) {
		return decodedToken.getHeaders().get(headerName).toString();
	}

	@Override
	public boolean hasHeaderParameter(@Nonnull String headerName) {
		return decodedToken.getHeaders().containsValue(headerName);
	}

	@Override
	public boolean hasClaim(@Nonnull String claimName) {
		return decodedToken.containsClaim(claimName);
	}

	@Nullable
	@Override
	public String getClaimAsString(@Nonnull String claimName) {
		return decodedToken.getClaimAsString(claimName);
	}

	@Override
	public List<String> getClaimAsStringList(@Nonnull String claimName) {
		return decodedToken.getClaimAsStringList(claimName);
	}

	@Nullable
	@Override
	public JsonObject getClaimAsJsonObject(@Nonnull String claimName) {
		return decodedToken.getClaim(claimName);
	}

	@Nullable
	@Override
	public Instant getExpiration() {
		return decodedToken.getExpiresAt();
	}

	@Override
	public boolean isExpired() {
		return Objects.requireNonNull(decodedToken.getExpiresAt(), "Token expiration time is missing")
				.isBefore(Instant.now());
	}

	@Nullable
	@Override
	public Instant getNotBefore() {
		return decodedToken.getNotBefore();
	}

	@Override
	public String getTokenValue() {
		return decodedToken.getTokenValue();
	}

	@Override
	public Principal getPrincipal() {
		return null;
	}

	@Override
	public Service getService() {
		return Service.IAS;
	}

	@Override
	public Set<String> getAudiences() {
		return new LinkedHashSet<>(getClaimAsStringList(AUDIENCE));
	}

	@Override
	public String getZoneId() {
		return decodedToken.getClaimAsString(SAP_GLOBAL_ZONE_ID);
	}

	@Override
	public String getClientId() {
		return decodedToken.getClaimAsString(SAP_GLOBAL_USER_ID);
	}
}
