package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

public class XsuaaJwtDecoderBuilder {

	private XsuaaServiceConfiguration configuration;
	int decoderCacheValidity = 900; // in seconds
	int decoderCacheSize = 100;
	OAuth2TokenValidator<Jwt>[] tokenValidators;

	/**
	 * Utility for building a JWT decoder configuration
	 *
	 * @param configuration
	 *            of the Xsuaa service
	 */
	public XsuaaJwtDecoderBuilder(XsuaaServiceConfiguration configuration) {
		this.configuration = configuration;
	}

	/**
	 * Assembles a JwtDecoder
	 *
	 * @return JwtDecoder
	 */
	public JwtDecoder build() {
		return new XsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize, tokenValidators);
	}
	
	/**
	 * Assembles a ReactiveJwtDecoder
	 *
	 * @return ReactiveJwtDecoder
	 */
	public ReactiveJwtDecoder buildAsReactive() {
		return new ReactiveXsuaaJwtDecoder(configuration, decoderCacheValidity, decoderCacheSize, tokenValidators);
	}

	/**
	 * Decoders cache the signing keys. Overwrite the cache time (default: 900
	 * seconds).
	 *
	 * @param timeInSeconds
	 *            time to cache the signing keys
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withDecoderCacheTime(int timeInSeconds) {
		this.decoderCacheValidity = timeInSeconds;
		return this;
	}

	/**
	 * Overwrite size of cached decoder (default: 100). Mainly relevant for multi
	 * tenant applications.
	 *
	 * @param size
	 *            number of cached decoders
	 * @return this
	 */
	public XsuaaJwtDecoderBuilder withDecoderCacheSize(int size) {
		this.decoderCacheSize = size;
		return this;
	}

	/**
	 * Configures clone token validator, in case of two xsuaa bindings (application
	 * and broker plan).
	 *
	 * @return this
	 */
	//var arg it is only being assigned to a OAuth2TokenValidator<Jwt>[], therefore its type safe.
	@SuppressWarnings("unchecked")
	public XsuaaJwtDecoderBuilder withTokenValidators(OAuth2TokenValidator<Jwt>... tokenValidators) {
		this.tokenValidators = tokenValidators;
		return this;
	}

}
