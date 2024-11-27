/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;

public class CombiningValidatorTest {

	public static final Token TOKEN = null;
	private static final String FIRST_ERROR_MESSAGE = "firstMessage";
	private static final String SECOND_ERROR_MESSAGE = "secondMessage";

	@Test
	public void validate_containsNoValidators_invalidResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(new ArrayList<>());

		ValidationResult validationResult = combiningValidator.validate(TOKEN);

		assertThat(validationResult.isValid()).isFalse();
	}

	@Test
	public void validate_twoValidValidators_validResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				TokenTestValidator.createValid(), TokenTestValidator.createValid());

		ValidationResult validationResult = combiningValidator.validate(TOKEN);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_invalidResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				TokenTestValidator.createInvalid(), TokenTestValidator.createInvalid());

		ValidationResult validationResult = combiningValidator.validate(TOKEN);

		assertThat(validationResult.isErroneous()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_containsOnlyOneErrorMessages() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				TokenTestValidator.createValid(), TokenTestValidator.createInvalid(FIRST_ERROR_MESSAGE),
				TokenTestValidator.createInvalid(SECOND_ERROR_MESSAGE));

		String error = combiningValidator.validate(TOKEN).getErrorDescription();

		assertThat(error).isEqualTo(FIRST_ERROR_MESSAGE);
	}

	@Test
	public void registerValidationListener_validValidator_callsOnValidationSuccess() {
		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(
				TokenTestValidator.createValid());
		ValidationListener validationListenerMock = Mockito.mock(ValidationListener.class);
		combiningValidator.registerValidationListener(validationListenerMock);

		combiningValidator.validate(TOKEN);

		Mockito.verify(validationListenerMock, times(1)).onValidationSuccess();
		Mockito.verifyNoMoreInteractions(validationListenerMock);
	}

	@Test
	public void registerValidationListener_invalidValidator_callsOnValidationSuccess() {
		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(
				TokenTestValidator.createInvalid());
		ValidationListener validationListenerMock = Mockito.mock(ValidationListener.class);
		combiningValidator.registerValidationListener(validationListenerMock);

		combiningValidator.validate(TOKEN);

		Mockito.verify(validationListenerMock, times(1)).onValidationError(any(ValidationResult.class));
		Mockito.verifyNoMoreInteractions(validationListenerMock);
	}

	@Test
	public void registerValidationListener_listenerIsRemoved_isNotCalled() {
		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(
				TokenTestValidator.createValid());
		ValidationListener validationListenerMock = Mockito.mock(ValidationListener.class);
		combiningValidator.registerValidationListener(validationListenerMock);
		combiningValidator.removeValidationListener(validationListenerMock);

		combiningValidator.validate(TOKEN);

		Mockito.verifyNoMoreInteractions(validationListenerMock);
	}

	@Test
	public void toString_containsValidatorName() {
		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(
				TokenTestValidator.createValid());

		assertThat(combiningValidator.toString()).contains(TokenTestValidator.class.getSimpleName());
	}

	@Test
	public void getValidators() {
		TokenTestValidator validator1 = TokenTestValidator.createValid();
		TokenTestValidator validator2 = TokenTestValidator.createInvalid();
		CombiningValidator<Token> cut = new CombiningValidator<Token>(validator1, validator2);

		assertThat(cut.getValidators()).containsExactly(validator1, validator2);
	}
}
