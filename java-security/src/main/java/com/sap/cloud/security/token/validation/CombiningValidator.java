package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.xsuaa.Assertions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * This is a special validator that combines several validators into one. By
 * default the validation stops after one invalid result has been found.
 *
 * @param <T>
 *            the type to be validated.
 */
public class CombiningValidator<T> implements Validator<T> {

	private final List<Validator<T>> validators;
	private final Set<ValidationListener> validationListeners = new HashSet<>();
	private static final Logger LOGGER = LoggerFactory.getLogger(CombiningValidator.class);

	public CombiningValidator(List<Validator<T>> validators) {
		Assertions.assertNotNull(validators, "validators must not be null.");
		this.validators = validators;
	}

	public CombiningValidator(Validator<T>... validators) {
		Assertions.assertNotNull(validators, "validators must not be null.");
		this.validators = Arrays.asList(validators);
	}

	@Override
	public ValidationResult validate(T t) {
		for (Validator<T> validator : validators) {
			ValidationResult result = validator.validate(t);
			if (result.isErroneous()) {
				LOGGER.debug("Validator that caused the failed validation: {}", validator.getClass().getName());
				validationListeners.forEach(listener -> listener.onValidationError(result));
				return result;
			}
		}
		return createValidationResult();
	}

	private ValidationResult createValidationResult() {
		if (validators.isEmpty()) {
			ValidationResult result = ValidationResults
					.createInvalid("CombiningValidator must contain at least one validator!");
			validationListeners.forEach(listener -> listener.onValidationError(result));
			return result;
		} else {
			validationListeners.forEach(ValidationListener::onValidationSuccess);
			return ValidationResults.createValid();
		}
	}

	public List<Validator<T>> getValidators() {
		return validators;
	}

	@Override
	public String toString() {
		StringBuilder validatorNames = new StringBuilder();
		for (Validator<T> v : validators) {
			validatorNames.append(v.getClass().getName()).append(',');
		}
		return validatorNames.toString();
	}

	/**
	 * Components that are interested in the result of the token validation can
	 * register a validation listener which is called whenever a token is validated.
	 * Listener must implement the {@link ValidationListener} interface.
	 *
	 * @param validationListener
	 *            the listener to be added.
	 */
	public void registerValidationListener(ValidationListener validationListener) {
		validationListeners.add(validationListener);
	}

	/**
	 * Use this method to remove a registered listener so that it is not called
	 * anymore.
	 *
	 * @param validationListener
	 *            the listener to be removed.
	 */
	public void removeValidationListener(ValidationListener validationListener) {
		validationListeners.remove(validationListener);
	}
}
