/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import org.hamcrest.number.OrderingComparison;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.CoreMatchers.allOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class OAuth2TokenResponseTest {

	@Test
	public void getExpiredDateFromAccessToken() {
		long expireInSeconds = 43199;
		Date minExpireDate = new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expireInSeconds));
		OAuth2TokenResponse accessToken = new OAuth2TokenResponse("e9511922b5e64c49ba0eedcc8d772e76", expireInSeconds,
				null);
		Date maxExpireDate = new Date(System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expireInSeconds));

		assertThat(accessToken.getExpiredAtDate(), allOf(OrderingComparison.greaterThanOrEqualTo(minExpireDate),
				OrderingComparison.lessThanOrEqualTo(maxExpireDate)));
	}

	@Test
	public void getExpiredFromAccessToken() {
		long expireInSeconds = 47299;
		Instant minExpireDate = getCurrentInstant().plusSeconds(expireInSeconds);

		OAuth2TokenResponse accessToken = new OAuth2TokenResponse(null, expireInSeconds, null);

		Instant maxExpireDate = getCurrentInstant().plusSeconds(expireInSeconds);

		assertThat(accessToken.getExpiredAt(), allOf(OrderingComparison.greaterThanOrEqualTo(minExpireDate),
				OrderingComparison.lessThanOrEqualTo(maxExpireDate)));
	}

	@Test
	public void getTokenType() {
		OAuth2TokenResponse tokenResponse = new OAuth2TokenResponse("accessToken", 47299, null, "bearer");
		assertEquals("bearer", tokenResponse.getTokenType());
		assertEquals("accessToken", tokenResponse.getAccessToken());
	}

	private Instant getCurrentInstant() {
		return Instant.ofEpochMilli(System.currentTimeMillis());
	}
}
