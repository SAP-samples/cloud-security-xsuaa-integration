/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.MockTokenBuilder;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static com.sap.cloud.security.TestConstants.*;
import static com.sap.cloud.security.token.MockTokenBuilder.NO_EXPIRE_DATE;
import static org.assertj.core.api.Assertions.assertThat;

public class JwtTimestampValidatorTest {

	private JwtTimestampValidator cut;
	private MockTokenBuilder tokenFactory;

	@BeforeEach
	public void setUp() {
		cut = new JwtTimestampValidator(() -> NOW, ONE_MINUTE);
		tokenFactory = new MockTokenBuilder();
	}

	@Test
	public void token_lacksExpiration_isNotValid() {
		Token token = tokenFactory.withExpiration(null).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
	}

	@Test
	public void tokenExpired_beforeClockSkewLeeway_isNotValidAndContainsErrorDescriptionWithDates() {
		Instant expiration = NOW.minus(ONE_MINUTE);
		Token token = tokenFactory.withExpiration(expiration).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrorDescription()).contains(NOW.toString()).contains(expiration.toString());
	}

	@Test
	public void tokenExpires_afterClockSkewLeeway_isValid() {
		Token token = tokenFactory.withExpiration(NOW.plus(ONE_MINUTE)).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenExpired_butStillInClockSkewLeeway_isValid() {
		Token token = tokenFactory.withExpiration(NOW.minus(ONE_MINUTE).plus(ONE_SECOND)).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenLacksNotBefore_isValid() {
		Token token = tokenFactory.withExpiration(NO_EXPIRE_DATE).withNotBefore(null).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenNotBefore_now_isValid() {
		Token token = tokenFactory.withExpiration(NO_EXPIRE_DATE).withNotBefore(NOW).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenNotBefore_insideClockSkewLeeway_isValid() {
		Token token = tokenFactory
				.withExpiration(NO_EXPIRE_DATE)
				.withNotBefore(NOW.plus(ONE_MINUTE).minus(ONE_SECOND))
				.build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenNotBefore_afterClockSkewLeeway_isNotValidAndContainsErrorDescription() {
		Instant inOneMinute = NOW.plus(ONE_MINUTE);
		Token token = tokenFactory.withExpiration(NO_EXPIRE_DATE).withNotBefore(inOneMinute).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isErroneous()).isTrue();
		assertThat(validationResult.getErrorDescription()).contains(NOW.toString()).contains(inOneMinute.toString());
	}

	@Test
	public void tokenNotBeforeIsValidButIsAlreadyExpired_isNotValid() {
		Token token = tokenFactory
				.withExpiration(NOW.minus(Duration.ofMinutes(2)))
				.withNotBefore(NOW)
				.build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isErroneous()).isTrue();
	}

	@Test
	public void tokenNotExpiredButNotBeforeNotReachedYet_isNotValid() {
		Instant inTwoMinutes = NOW.plus(Duration.ofMinutes(2));
		Token token = tokenFactory
				.withExpiration(inTwoMinutes)
				.withNotBefore(inTwoMinutes)
				.build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isErroneous()).isTrue();
	}

}
