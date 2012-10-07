package org.apache.shiro.iwa.authc;

public interface IwaAuthenticationStrategy {
	/**
	 * 
	 * 
	 * @return
	 */
	boolean supportsNegotiate( );
	
	/**
	 * 
	 * 
	 * @return
	 */
	boolean supportsNtlm( );
	
	/**
	 * 
	 * 
	 * @param request
	 * @return
	 */
	IwaAuthenticationResponse authenticate( IwaAuthenticationRequest request );
}
