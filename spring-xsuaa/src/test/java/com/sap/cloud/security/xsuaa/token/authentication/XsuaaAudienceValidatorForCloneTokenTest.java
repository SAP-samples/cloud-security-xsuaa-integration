/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication;

import com.nimbusds.jwt.JWTClaimsSet;
import com.sap.cloud.security.xsuaa.DummyXsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import com.sap.cloud.security.xsuaa.token.TokenClaims;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class XsuaaAudienceValidatorForCloneTokenTest {

	private JWTClaimsSet.Builder claimsBuilder;
	private String XSUAA_BROKER_XSAPPNAME = "brokerplanmasterapp!b123";
	private String XSUAA_BROKER_CLIENT_ID = "sb-" + XSUAA_BROKER_XSAPPNAME;
	private XsuaaAudienceValidator cut;

	@BeforeEach
	public void setup() {
		XsuaaServiceConfiguration serviceConfiguration = new DummyXsuaaServiceConfiguration("sb-test1!t1", "test1!t1");
		cut = new XsuaaAudienceValidator(serviceConfiguration);
		cut.configureAnotherXsuaaInstance(XSUAA_BROKER_XSAPPNAME, XSUAA_BROKER_CLIENT_ID);

		claimsBuilder = new JWTClaimsSet.Builder().issueTime(new Date()).expirationTime(JwtGenerator.NO_EXPIRE_DATE);
	}

	@Test
	public void tokenWithClientId_like_brokerClientId_shouldBeIgnored() {
		claimsBuilder.claim(TokenClaims.CLAIM_CLIENT_ID, XSUAA_BROKER_CLIENT_ID);

		OAuth2TokenValidatorResult result = cut.validate(JwtGenerator.createFromClaims(claimsBuilder.build()));
		Assertions.assertFalse(result.hasErrors());
	}

	@Test
	public void cloneTokenClientId_like_brokerClientId_shouldBeAccepted() {
		claimsBuilder.claim(TokenClaims.CLAIM_CLIENT_ID, "sb-clone1!b22|" + XSUAA_BROKER_XSAPPNAME);

		OAuth2TokenValidatorResult result = cut.validate(JwtGenerator.createFromClaims(claimsBuilder.build()));
		Assertions.assertFalse(result.hasErrors());
	}

	@Test
	public void cloneTokenClientId_unlike_brokerClientId_raisesError() {
		claimsBuilder.claim(TokenClaims.CLAIM_CLIENT_ID, "sb-clone1!b22|ANOTHERAPP!b12");

		OAuth2TokenValidatorResult result = cut.validate(JwtGenerator.createFromClaims(claimsBuilder.build()));
		Assertions.assertTrue(result.hasErrors());

		List<OAuth2Error> errors = new ArrayList<>(result.getErrors());
		assertThat(errors.get(0).getDescription(),
				is("Jwt token with allowed audiences [] matches none of these: [test1!t1, brokerplanmasterapp!b123]"));
		assertThat(errors.get(0).getErrorCode(), is(OAuth2ErrorCodes.INVALID_CLIENT));
	}

}
