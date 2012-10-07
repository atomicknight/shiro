package org.apache.shiro.iwa.authc;

public class IwaAuthenticationResponse {
	private final IwaAuthenticationScheme scheme;
	private final boolean complete;
	private final byte[] token;
	private final Object principal;
	
	/**
	 * 
	 * @param scheme TODO
	 * @param complete
	 * @param token
	 * @param principal
	 */
	public IwaAuthenticationResponse( IwaAuthenticationScheme scheme,
			boolean complete, byte[] token, Object principal ) {
		this.scheme = scheme;
		this.complete = complete;
		this.token = token;
		this.principal = principal;
	}
	
	/**
	 * @return the scheme
	 */
	public IwaAuthenticationScheme getScheme( ) {
		return scheme;
	}
	
	/**
	 * Returns whether the authentication process has completed.
	 * 
	 * @return
	 */
	public boolean isComplete( ) {
		return complete;
	}
	
	/**
	 * Returns the response token or {@code null} if there is no token to return.
	 * 
	 * @return
	 */
	public byte[] getToken( ) {
		return token;
	}
	
	/**
	 * Returns the authenticated principal or {@code null} if the authentication is incomplete or has failed.
	 * 
	 * @return
	 */
	public Object getPrincipal( ) {
		return principal;
	}
}
