package com.sap.cloud.security.xsuaa.jwt;

/**
 * A Jwt token consists of three parts, separated by ".":
 * header.payload.signature
 *
 * Use {@code Base64JwtDecoder.getInstance().decode(token)} to get a {@link DecodedJwt} instance.
 */

public interface DecodedJwt {

	/**
	 * Get the base64 decoded header of the jwt as UTF-8 String.
	 *
	 * @return the decoded header.
	 */
	String getHeader();

	/**
	 * Get the base64 decoded payload of the jwt as UTF-8 String.
	 *
	 * @return the decoded payload.
	 */
	String getPayload();

	/**
	 * Get the encoded signature of the jwt.
	 *
	 * @return the decoded signature.
	 */
	String getSignature();

	/**
	 * Get the original encoded access token.
	 *
	 * <p>
	 * Never expose this token via log or via HTTP.
	 *
	 * @return jwt token
	 */
	String getEncodedToken();

}
