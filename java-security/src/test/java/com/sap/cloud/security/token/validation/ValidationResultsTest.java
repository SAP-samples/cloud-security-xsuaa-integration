/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ValidationResultsTest {

	@Test
	public void createInvalid() {
		String errorMessage = "An error message";
		ValidationResult validationResult = ValidationResults.createInvalid(errorMessage);

		assertThat(validationResult.isErroneous()).isTrue();
		assertThat(validationResult.getErrorDescription()).isEqualTo(errorMessage);
	}

	@Test
	public void createValid() {
		ValidationResult validationResult = ValidationResults.createValid();

		assertThat(validationResult.isValid()).isTrue();
		assertThat(validationResult.toString()).contains("Validation was successful");
	}

	@Test
	public void createInvalidWithTemplateString() {
		String errorMessageTemplate = "An error message {} {} {}";
		String[] args = { "first", "second", "third" };
		ValidationResult validationResult = ValidationResults.createInvalid(errorMessageTemplate, args[0], args[1],
				args[2]);

		assertThat(validationResult.isErroneous()).isTrue();
		assertThat(validationResult.getErrorDescription()).isEqualTo("An error message first second third");
	}

	@Test
	public void createInvalidWithTemplateString_tooManyPlaceholders_areIgnored() {
		String errorMessageTemplate = "An error message {} {} {}";
		String onlyOne = "first";
		ValidationResult validationResult = ValidationResults.createInvalid(errorMessageTemplate, onlyOne);

		assertThat(validationResult.isErroneous()).isTrue();
		assertThat(validationResult.getErrorDescription()).isEqualTo("An error message first {} {}");
	}

	@Test
	public void createInvalidWithTemplateString_tooManyArguments_areIgnored() {
		String errorMessageTemplate = "An error message {}";
		String[] args = { "first", "second", "third" };
		ValidationResult validationResult = ValidationResults.createInvalid(errorMessageTemplate, args);

		assertThat(validationResult.isErroneous()).isTrue();
		assertThat(validationResult.getErrorDescription()).isEqualTo("An error message first");
	}

}
