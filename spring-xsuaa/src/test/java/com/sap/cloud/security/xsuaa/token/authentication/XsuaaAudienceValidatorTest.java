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
import org.springframework.security.oauth2.jwt.Jwt;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class XsuaaAudienceValidatorTest {

	private Jwt tokenWithAudience;
	private Jwt tokenWithoutAudience;
	private Jwt cloneTokenWithAudience;

	private XsuaaServiceConfiguration serviceConfigurationSameClientId;
	private XsuaaServiceConfiguration serviceConfigurationOtherGrantedClientId;
	private XsuaaServiceConfiguration serviceConfigurationUnGrantedClientId;
	private XsuaaServiceConfiguration serviceConfigurationBrokerPlan;

	private JWTClaimsSet.Builder claimsBuilder;

	@BeforeEach
	public void setup() throws IOException {
		serviceConfigurationSameClientId = new DummyXsuaaServiceConfiguration("sb-test1!t1", "test1!t1");
		serviceConfigurationOtherGrantedClientId = new DummyXsuaaServiceConfiguration("sb-test2!t1", "test2!t1");
		serviceConfigurationUnGrantedClientId = new DummyXsuaaServiceConfiguration("sb-test3!t1", "test3!t1");
		serviceConfigurationBrokerPlan = new DummyXsuaaServiceConfiguration("sb-test3!b1", "test3!b1");
		tokenWithAudience = new JwtGenerator().createFromTemplate("/audience_1.txt");
		tokenWithoutAudience = new JwtGenerator().createFromTemplate("/audience_2.txt");
		cloneTokenWithAudience = new JwtGenerator().createFromTemplate("/audience_3.txt");

		claimsBuilder = new JWTClaimsSet.Builder().issueTime(new Date()).expirationTime(JwtGenerator.NO_EXPIRE_DATE);
		claimsBuilder.claim(TokenClaims.CLAIM_CLIENT_ID, "sb-test1!t1");
	}

	@Test
	public void testSameClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationSameClientId)
				.validate(tokenWithAudience);
		Assertions.assertFalse(result.hasErrors());
	}

	@Test
	public void testSameClientIdWithoutAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationSameClientId)
				.validate(tokenWithoutAudience);
		Assertions.assertFalse(result.hasErrors());
	}

	@Test
	public void testExtractAudiencesFromTokenScopes() {
		Jwt token = new JwtGenerator()
				.addScopes("test1!t1.read", "test2!t1.read", "test2!t1.write", ".scopeWithoutAppId").getToken();
		Set<String> audiences = XsuaaAudienceValidator.getAllowedAudiences(token);
		assertThat(audiences.size(), is(2));
		assertThat(audiences, hasItem("test1!t1"));
		assertThat(audiences, hasItem("test2!t1"));
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudience);
		Assertions.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndDot() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(
				new DummyXsuaaServiceConfiguration("sb-test4!t1", "test4!t1")).validate(tokenWithAudience);
		Assertions.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationUnGrantedClientId)
				.validate(tokenWithAudience);
		Assertions.assertTrue(result.hasErrors());
	}

	@Test
	public void testUnGrantedClientId() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationUnGrantedClientId)
				.validate(tokenWithAudience);
		Assertions.assertTrue(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceButScopes() {
		List<String> scopes = new ArrayList<String>();
		scopes.add("test2!t1.Display");
		claimsBuilder.claim(TokenClaims.CLAIM_SCOPES, scopes);

		Jwt tokenWithoutAudienceButScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudienceButScopes);
		Assertions.assertFalse(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndMatchingScopes() {
		List<String> scopes = new ArrayList<String>();
		scopes.add("test3!t1.Display");
		claimsBuilder.claim(TokenClaims.CLAIM_SCOPES, scopes);

		Jwt tokenWithoutAudienceButScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudienceButScopes);
		Assertions.assertTrue(result.hasErrors());
		List<OAuth2Error> errors = new ArrayList<>(result.getErrors());
		String expectedDescription = "Jwt token with allowed audiences [test3!t1] matches none of these: [test2!t1]";
		assertThat(errors.get(0).getDescription(), is(expectedDescription));
		assertThat(errors.get(0).getErrorCode(), is(OAuth2ErrorCodes.INVALID_CLIENT));
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndScopes() {
		Jwt tokenWithoutAudienceAndScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudienceAndScopes);
		Assertions.assertTrue(result.hasErrors());
	}

	@Test
	public void testOtherGrantedClientIdWithoutAudienceAndEmptyScopes() {
		claimsBuilder.claim(TokenClaims.CLAIM_SCOPES, "[]");
		Jwt tokenWithoutAudienceAndScopes = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationOtherGrantedClientId)
				.validate(tokenWithoutAudienceAndScopes);
		Assertions.assertTrue(result.hasErrors());
	}

	@Test
	public void testTokenWithoutClientId() {
		claimsBuilder.claim(TokenClaims.CLAIM_CLIENT_ID, "");
		Jwt tokenWithoutClientId = JwtGenerator.createFromClaims(claimsBuilder.build());
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationSameClientId)
				.validate(tokenWithoutClientId);
		Assertions.assertTrue(result.hasErrors());
	}

	@Test
	public void testBrokerCloneWithAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationBrokerPlan)
				.validate(cloneTokenWithAudience);
		Assertions.assertFalse(result.hasErrors());
	}

	@Test
	public void testBrokerCloneWithoutAudience() {
		OAuth2TokenValidatorResult result = new XsuaaAudienceValidator(serviceConfigurationBrokerPlan)
				.validate(cloneTokenWithAudience);
		Assertions.assertFalse(result.hasErrors());
	}

}
