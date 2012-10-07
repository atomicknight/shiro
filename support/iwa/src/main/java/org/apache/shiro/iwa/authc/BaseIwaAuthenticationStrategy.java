package org.apache.shiro.iwa.authc;

import org.apache.shiro.iwa.ntlm.NtlmConstants;

public abstract class BaseIwaAuthenticationStrategy implements
		IwaAuthenticationStrategy {
	protected static final int INITIAL_NTLM_MESSAGE_TYPE = 1;
	
	protected BaseIwaAuthenticationStrategy( ) {
		// No-op
	}
	
	public IwaAuthenticationResponse authenticate(
			IwaAuthenticationRequest request ) {
		if( request.getScheme( ) == IwaAuthenticationScheme.SPNEGO ) {
			// Some browsers will send raw NTLMSSP tokens with a Negotiate
			// scheme
			byte[] token = request.getToken( );
			if( isNtlmsspToken( token ) && supportsNtlm( ) ) {
				return acceptNtlmSecContext( request.getConnectionId( ), token );
			} else if( supportsNegotiate( ) ) {
				return acceptNegotiateSecContext(
						request.getConnectionId( ),
						token );
			}
		} else if( request.getScheme( ) == IwaAuthenticationScheme.NTLM
				&& supportsNtlm( ) ) {
			return acceptNtlmSecContext(
					request.getConnectionId( ),
					request.getToken( ) );
		}
		
		// Can't support the requested authentication scheme
		return new IwaAuthenticationResponse( null, true, null, null );
	}
	
	protected IwaAuthenticationResponse acceptNegotiateSecContext(
			String connectionId, byte[] token )
			throws UnsupportedOperationException {
		throw new UnsupportedOperationException( getClass( ).getName( )
				+ " does not support the " + IwaAuthenticationScheme.SPNEGO
				+ " scheme" );
	}
	
	protected IwaAuthenticationResponse acceptNtlmSecContext(
			String connectionId, byte[] token )
			throws UnsupportedOperationException {
		throw new UnsupportedOperationException( getClass( ).getName( )
				+ " does not support the " + IwaAuthenticationScheme.NTLM
				+ " scheme" );
	}
	
	protected static boolean isNtlmsspToken( byte[] token ) {
		boolean match = ( token.length > NtlmConstants.NTLMSSP_FINGERPRINT.length );
		for( int i = 0; match && i < NtlmConstants.NTLMSSP_FINGERPRINT.length; i++ ) {
			match = ( token[i] == NtlmConstants.NTLMSSP_FINGERPRINT[i] );
		}
		return match;
	}
}
