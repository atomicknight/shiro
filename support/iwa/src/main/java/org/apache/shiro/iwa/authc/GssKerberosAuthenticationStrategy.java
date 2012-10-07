package org.apache.shiro.iwa.authc;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.directory.server.kerberos.shared.io.decoder.ApplicationRequestDecoder;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.iwa.gss.GSSUtils;
import org.apache.shiro.iwa.kerberos.KerberosConstants;
import org.apache.shiro.iwa.kerberos.KerberosUtils;
import org.apache.shiro.iwa.spnego.NegTokenInit;
import org.apache.shiro.iwa.spnego.NegTokenResp;
import org.apache.shiro.iwa.spnego.NegTokenResp.NegState;
import org.apache.shiro.iwa.spnego.SpnegoConstants;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GssKerberosAuthenticationStrategy extends
		BaseIwaAuthenticationStrategy {
	private static final Logger LOG = LoggerFactory
			.getLogger( GssKerberosAuthenticationStrategy.class );
	
	private GSSManager gssManager;
	private String loginContextName = "spnego";
	
	public GssKerberosAuthenticationStrategy( ) {
		this( GSSManager.getInstance( ) );
	}
	
	public GssKerberosAuthenticationStrategy( GSSManager gssManager ) {
		this.gssManager = gssManager;
	}
	
	public boolean supportsNegotiate( ) {
		return true;
	}
	
	public boolean supportsNtlm( ) {
		return false;
	}
	
	@Override
	protected IwaAuthenticationResponse acceptNegotiateSecContext(
			String connectionId, byte[] token )
			throws UnsupportedOperationException {
		NegTokenInit spnegoToken = new NegTokenInit( token );
		
		List<String> mechanisms = spnegoToken.getMechTypes( );
		if( LOG.isDebugEnabled( ) ) {
			LOG.debug(
					"initNegotiateSecContext: Received mechanisms {}",
					mechanisms );
		}
		
		// TODO: Check if this ever happens
		if( mechanisms.isEmpty( ) ) {
			// No mechanisms provided - can't authenticate
			return new IwaAuthenticationResponse(
					IwaAuthenticationScheme.SPNEGO,
					true,
					null,
					null );
		}
		
		byte[] mechanismToken = spnegoToken.getMechToken( );
		if( mechanismToken != null ) {
			// Determine which mechanism was selected
			String mechanism = GSSUtils.getMechanism( mechanismToken );
			if( KerberosConstants.KERBEROS_V5_MECHANISM.equals( mechanism ) ) {
				// Have a Kerberos v5 token - use it for authenticatication
				return acceptKerberosSecContext(
						token,
						getServiceName( mechanismToken ) );
			}
		}
		
		// Check if the client supports Kerberos v5
		for( String mechanism : mechanisms ) {
			if( KerberosConstants.KERBEROS_V5_MECHANISM.equals( mechanism ) ) {
				// Client supports Kerberos v5 - build negotiation token
				return new IwaAuthenticationResponse(
						IwaAuthenticationScheme.SPNEGO,
						false,
						new NegTokenResp(
								NegState.ACCEPT_INCOMPLETE,
								mechanism,
								null,
								null ).toByteArray( ), null );
			}
		}
		
		// Client doesn't support Kerberos v5 - can't authenticate
		return new IwaAuthenticationResponse(
				IwaAuthenticationScheme.SPNEGO,
				true,
				null,
				null );
	}
	
	protected IwaAuthenticationResponse acceptKerberosSecContext( byte[] token,
			String serviceName ) {
		try {
			GSSContext context = gssManager.createContext( getServerCredential(
					getSubject( loginContextName ),
					gssManager.createName(
							serviceName,
							GSSName.NT_HOSTBASED_SERVICE ) ) );
			byte[] responseToken = context.acceptSecContext(
					token,
					0,
					token.length );
			return new IwaAuthenticationResponse(
					IwaAuthenticationScheme.SPNEGO,
					context.isEstablished( ),
					responseToken,
					context.getSrcName( ).toString( ) );
		} catch( GSSException e ) {
			// TODO: Check exception code and re-throw more appropriate exceptions
			throw new AuthenticationException( "Login failed", e );
		}
	}
	
	protected Subject getSubject( String loginContextName ) {
		try {
			LoginContext loginContext = new LoginContext( loginContextName );
			loginContext.login( );
			return loginContext.getSubject( );
		} catch( LoginException e ) {
			throw new AuthenticationException(
					"Unable to perform initial login",
					e );
		}
	}
	
	protected GSSCredential getServerCredential( Subject subject,
			final GSSName serviceName ) {
		try {
			return Subject.doAs(
					subject,
					new PrivilegedExceptionAction<GSSCredential>( ) {
						public GSSCredential run( ) throws Exception {
							return gssManager.createCredential(
									serviceName,
									GSSCredential.INDEFINITE_LIFETIME,
									SpnegoConstants.SPNEGO_OID,
									GSSCredential.ACCEPT_ONLY );
						}
					} );
		} catch( PrivilegedActionException e ) {
			throw new AuthenticationException(
					"Could not generate server credential",
					e );
		}
	}
	
	protected String getServiceName( byte[] token ) {
		// Extract the SPN from the token
		List<String> spnParts;
		try {
			spnParts = new ApplicationRequestDecoder( )
					.decode( KerberosUtils.unwrap( token ) )
					.getTicket( )
					.getSName( )
					.getNames( );
		} catch( IllegalArgumentException e ) {
			throw new AuthenticationException(
					"Unable to extract Kerberos token",
					e );
		} catch( IOException e ) {
			throw new AuthenticationException(
					"Unable to decode Kerberos token",
					e );
		}
		if( spnParts.size( ) != 2 ) {
			throw new AuthenticationException(
					"Unexpected number of parts for service principal name: "
							+ spnParts );
		}
		
		return spnParts.get( 0 ) + "@" + spnParts.get( 1 );
	}
}
