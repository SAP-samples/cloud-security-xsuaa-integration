package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;

import java.security.Principal;

import static com.sap.cloud.security.token.TokenClaims.SAP_GLOBAL_USER_ID;

/**
 * You can get further token claims from here: {@link TokenClaims}.
 */
public class SapIdToken extends AbstractToken {
	public SapIdToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	public SapIdToken(@Nonnull String idToken) {
		super(idToken);
	}

	@Override
	public Principal getPrincipal() {
		return createPrincipalByName(getClaimAsString(SAP_GLOBAL_USER_ID));
	}

	@Override
	public Service getService() {
		return Service.IAS;
	}

}
