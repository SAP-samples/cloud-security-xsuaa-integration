/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.CombiningValidator;
import com.sap.cloud.security.token.validation.TokenTestValidator;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class JwtValidatorBuilderTest {

	OAuth2ServiceConfigurationBuilder xsuaaConfigBuilder = OAuth2ServiceConfigurationBuilder.forService(XSUAA)
			.withDomains("auth.com")
			.withProperty(ServiceConstants.XSUAA.APP_ID, "test-app!t123")
			.withClientId("sb-test-app!t123");

	@BeforeEach
	public void setUp() {
		Mockito.mockitoSession().initMocks();
	}

	@Test
	public void sameServiceConfiguration_getSameInstance() {
		TokenTestValidator.createValid();
		OAuth2ServiceConfiguration configuration = xsuaaConfigBuilder.build();
		JwtValidatorBuilder builder_1 = JwtValidatorBuilder.getInstance(configuration);
		JwtValidatorBuilder builder_2 = JwtValidatorBuilder.getInstance(configuration);
		JwtValidatorBuilder builder_3 = JwtValidatorBuilder.getInstance(xsuaaConfigBuilder.build());
		assertThat(builder_1).isSameAs(builder_2).isSameAs(builder_3);
	}

	@Test
	public void withAudienceValidator_overridesXsuaaJwtAudienceValidator() {
		TokenTestValidator validator = TokenTestValidator.createValid();
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(xsuaaConfigBuilder.build())
				.withAudienceValidator(validator)
				.build()
				.getValidators();
		assertThat(validators).contains(validator)
				.doesNotHaveAnyElementsOfTypes(JwtAudienceValidator.class);
	}

	@Test
	public void build_containsAllDefaultValidators() {
		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(xsuaaConfigBuilder.build()).build()
				.getValidators();

		assertThat(validators)
				.hasSize(3)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(JwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class);
	}

	@Test
	public void buildLegacy_containsAllDefaultValidators() {
		List<Validator<Token>> validators = JwtValidatorBuilder
				.getInstance(xsuaaConfigBuilder.runInLegacyMode(true).build())
				.build()
				.getValidators();

		assertThat(validators)
				.hasSize(3)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(JwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class);
	}

	@Test
	public void buildIas_containsAllDefaultValidators() {
		OAuth2ServiceConfigurationBuilder iasConfigBuilder = OAuth2ServiceConfigurationBuilder.forService(IAS)
				.withDomains("app.auth.com")
				.withClientId("T0123456");

		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(iasConfigBuilder.build())
				.build()
				.getValidators();

		assertThat(validators)
				.hasSize(4)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.hasAtLeastOneElementOfType(JwtAudienceValidator.class)
				.hasAtLeastOneElementOfType(JwtSignatureValidator.class)
				.hasAtLeastOneElementOfType(JwtIssuerValidator.class);
	}

	@Test
	public void build_ias_withTenantIdCheckDisabled() throws IOException {
		OAuth2ServiceConfigurationBuilder iasConfigBuilder = OAuth2ServiceConfigurationBuilder.forService(IAS)
				.withDomains("myauth.com")
				.withClientId("T000310");
		OAuth2TokenKeyService tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		OAuth2ServiceEndpointsProvider endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		OidcConfigurationService oidcConfigServiceMock = Mockito.mock(OidcConfigurationService.class);

		when(tokenKeyServiceMock.retrieveTokenKeys(any(), anyMap()))
				.thenReturn(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));
		when(endpointsProviderMock.getJwksUri()).thenReturn(URI.create("https://application.myauth.com/jwks_uri"));
		when(oidcConfigServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);

		CombiningValidator<Token> combiningValidator = JwtValidatorBuilder.getInstance(iasConfigBuilder.build())
				.withOAuth2TokenKeyService(tokenKeyServiceMock)
				.withOidcConfigurationService(oidcConfigServiceMock)
				.disableTenantIdCheck()
				.build();

		assertThat(combiningValidator.validate(new SapIdToken(
						"eyJraWQiOiJkZWZhdWx0LWtpZCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJQMTc2OTQ1IiwiYXVkIjoiVDAwMDMxMCIsInVzZXJfdXVpZCI6IjEyMzQ1Njc4OTAiLCJpc3MiOiJodHRwczovL2FwcGxpY2F0aW9uLm15YXV0aC5jb20iLCJleHAiOjY5NzQwMzE2MDAsImdpdmVuX25hbWUiOiJqb2huIiwiZW1haWwiOiJqb2huLmRvZUBlbWFpbC5vcmciLCJjaWQiOiJUMDAwMzEwIn0.Svrb5PriAuHOdhTFXiicr_qizHiby6b73SdovJAFnWCPDr0r8mmFoEWXjJmdLdw08daNzt8ww_r2khJ-rusUZVfiZY3kyRV1hfeChpNROGfmGbfN62KSsYBPi4dBMIGRz8SqkF6nw5nTC-HOr7Gd8mtZjG9KZYC5fKYOYRvbAZN_xyvLDzFUE6LgLmiT6fV7fHPQi5NSUfawpWQbIgK2sJjnp-ODTAijohyxQNuF4Lq1Prqzjt2QZRwvbskTcYM3gK5fgt6RYDN6MbARJIVFsb1Y7wZFg00dp2XhdFzwWoQl6BluvUL8bL73A8iJSam0csm1cuG0A7kMF9spy_whQw"))
				.isValid()).isTrue();
	}

	@Test
	public void buildWithAnotherValidator_containsAddedValidator() {
		TokenTestValidator tokenValidator = TokenTestValidator.createValid();

		List<Validator<Token>> validators = JwtValidatorBuilder.getInstance(xsuaaConfigBuilder.build())
				.with(tokenValidator)
				.build()
				.getValidators();

		assertThat(validators)
				.hasAtLeastOneElementOfType(JwtTimestampValidator.class)
				.contains(tokenValidator);
	}

	@Test
	public void configureOtherServiceInstances() {
		Collection clientIds = new ArrayList();

		OAuth2ServiceConfiguration xsuaaConfig1 = xsuaaConfigBuilder.build();
		OAuth2ServiceConfiguration xsuaaConfig2 = OAuth2ServiceConfigurationBuilder.forService(XSUAA)
				.withClientId("sb-test-app2!b222").build();
		OAuth2ServiceConfiguration xsuaaConfig3 = OAuth2ServiceConfigurationBuilder.forService(XSUAA)
				.withClientId("sb-test-app3!b333").build();

		clientIds.add(xsuaaConfig1.getClientId());
		clientIds.add(xsuaaConfig2.getClientId());
		clientIds.add(xsuaaConfig3.getClientId());

		CombiningValidator<Token> combiningValidator = JwtValidatorBuilder
				.getInstance(xsuaaConfig1)
				.configureAnotherServiceInstance(xsuaaConfig2)
				.configureAnotherServiceInstance(xsuaaConfig3)
				.build();

		for (Validator validator : combiningValidator.getValidators()) {
			if (validator instanceof JwtAudienceValidator) {
				assertThat(((JwtAudienceValidator) validator).getTrustedClientIds()).containsAll(clientIds);
				return;
			}
		}
		Assertions.fail("No JwtAudienceValidator found that contains all clientIds!"); // should never be called
	}

}