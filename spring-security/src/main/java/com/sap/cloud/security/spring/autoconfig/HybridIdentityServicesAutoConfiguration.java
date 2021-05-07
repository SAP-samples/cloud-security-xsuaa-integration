package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.spring.config.XsuaaServiceConfigurations;
import com.sap.cloud.security.spring.token.authentication.JwtDecoderBuilder;
import com.sap.cloud.security.spring.config.IdentityServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type.SERVLET;

/**
 * {@link EnableAutoConfiguration} exposes a {@link JwtDecoder}, which has the
 * standard Spring Security Jwt validators as well as the SCP identity
 * provider-specific validators.
 *
 * Activates when there is a bean of type {@link Jwt} configured in the context.
 *
 * <p>
 * Can be disabled with
 * {@code @EnableAutoConfiguration(exclude={HybridIdentityServicesAutoConfiguration.class})}
 * or with property {@code sap.spring.security.hybrid.auto = false}.
 */
@Configuration
@ConditionalOnClass(Jwt.class)
@ConditionalOnProperty(name = "sap.spring.security.hybrid.auto", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({ XsuaaServiceConfiguration.class, IdentityServiceConfiguration.class,
		XsuaaServiceConfigurations.class })
@AutoConfigureBefore(OAuth2ResourceServerAutoConfiguration.class) // imports OAuth2ResourceServerJwtConfiguration which
																	// specifies JwtDecoder
class HybridIdentityServicesAutoConfiguration {
	private static final Logger LOGGER = LoggerFactory.getLogger(HybridIdentityServicesAutoConfiguration.class);

	HybridIdentityServicesAutoConfiguration() {
		// no need to create an instance
	}

	@Configuration
	@ConditionalOnMissingBean({ JwtDecoder.class })
	@ConditionalOnWebApplication(type = SERVLET)
	static class JwtDecoderConfigurations {
		XsuaaServiceConfigurations xsuaaConfigs;

		JwtDecoderConfigurations(XsuaaServiceConfigurations xsuaaConfigs) {
			this.xsuaaConfigs = xsuaaConfigs;
		}

		@Bean
		@ConditionalOnProperty("sap.security.services.xsuaa.uaadomain")
		public JwtDecoder hybridJwtDecoder(XsuaaServiceConfiguration xsuaaConfig,
				IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures HybridJwtDecoder.");
			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.withXsuaaServiceConfiguration(xsuaaConfig)
					.build();
		}

		@Bean
		@Primary
		@ConditionalOnProperty("sap.security.services.xsuaa[0].uaadomain")
		public JwtDecoder hybridJwtDecoderMultiXsuaaServices(IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures HybridJwtDecoder when bound to multiple xsuaa service instances.");
			return new JwtDecoderBuilder()
					.withIasServiceConfiguration(identityConfig)
					.withXsuaaServiceConfigurations(xsuaaConfigs.getConfigurations())
					.build();
		}

		@Bean
		@ConditionalOnProperty("sap.security.services.identity.domain")
		@ConditionalOnMissingBean(JwtDecoder.class)
		public JwtDecoder iasJwtDecoder(IdentityServiceConfiguration identityConfig) {
			LOGGER.debug("auto-configures IasJwtDecoder.");
				return new JwtDecoderBuilder()
						.withIasServiceConfiguration(identityConfig)
						.build();
		}
	}

}
