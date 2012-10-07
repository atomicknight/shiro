package org.apache.shiro.iwa.authc;

public class IwaAuthenticationRequest {
	private final String connectionId;
	private final IwaAuthenticationScheme scheme;
	private final byte[] token;
	
	/**
	 * @param connectionId
	 * @param scheme
	 * @param token
	 */
	public IwaAuthenticationRequest( String connectionId, IwaAuthenticationScheme scheme,
			byte[] token ) {
		this.connectionId = connectionId;
		this.scheme = scheme;
		this.token = token;
	}

	/**
	 * @return the connectionId
	 */
	public String getConnectionId( ) {
		return connectionId;
	}

	/**
	 * @return the scheme
	 */
	public IwaAuthenticationScheme getScheme( ) {
		return scheme;
	}

	/**
	 * @return the token
	 */
	public byte[] getToken( ) {
		return token;
	}
}
