package org.apache.shiro.iwa;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.iwa.authc.AuthenticatedIwaToken;
import org.apache.shiro.iwa.authc.IwaAuthenticationRequest;
import org.apache.shiro.iwa.authc.IwaAuthenticationResponse;
import org.apache.shiro.iwa.authc.IwaAuthenticationScheme;
import org.apache.shiro.iwa.authc.IwaAuthenticationStrategy;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IwaHttpFilter extends AuthenticationFilter {
	private static final Logger log = LoggerFactory
			.getLogger( IwaHttpFilter.class );
	
	private static final String HTTP_SCHEME_NEGOTIATE = IwaAuthenticationScheme.SPNEGO
			.getValue( );
	private static final String HTTP_SCHEME_NTLM = IwaAuthenticationScheme.NTLM
			.getValue( );
	
	private IwaAuthenticationStrategy authenticationStrategy;
	
	public IwaAuthenticationStrategy getAuthenticationStrategy( ) {
		return authenticationStrategy;
	}
	
	public void setAuthenticationStrategy(
			IwaAuthenticationStrategy authenticationStrategy ) {
		this.authenticationStrategy = authenticationStrategy;
	}
	
	@Override
	protected boolean onAccessDenied( ServletRequest request,
			ServletResponse response ) throws Exception {
		boolean loggedIn = false;
		HttpServletResponse httpResponse = WebUtils.toHttp( response );
		
		if( isLoginRequest( request, response ) ) {
			IwaAuthenticationResponse result = authenticationStrategy
					.authenticate( buildAuthenticationRequest( request ) );
			Object principal = result.getPrincipal( );
			if( result.isComplete( ) && principal != null ) {
				Subject subject = getSubject( request, response );
				subject.login( new AuthenticatedIwaToken( principal ) );
				loggedIn = true;
			} else {
				httpResponse.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
			}
			
			IwaAuthenticationScheme scheme = result.getScheme( );
			byte[] token = result.getToken( );
			if( scheme != null && token != null ) {
				httpResponse.addHeader( "WWW-Authenticate", scheme.getValue( )
						+ " " + token );
			}
		} else {
			// Send challenge
			httpResponse.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
			if( authenticationStrategy.supportsNegotiate( ) ) {
				httpResponse.addHeader(
						"WWW-Authenticate",
						HTTP_SCHEME_NEGOTIATE );
			}
			if( authenticationStrategy.supportsNtlm( ) ) {
				httpResponse.addHeader( "WWW-Authenticate", HTTP_SCHEME_NTLM );
			}
		}
		
		return loggedIn;
	}
	
	@Override
	protected final boolean isLoginRequest( ServletRequest request,
			ServletResponse response ) {
		boolean loginRequest = false;
		
		String[] parts = extractAuthzHeaderParts( request );
		if( parts != null ) {
			String scheme = parts[0];
			loginRequest = ( HTTP_SCHEME_NEGOTIATE.equals( scheme ) && authenticationStrategy
					.supportsNegotiate( ) )
					|| ( HTTP_SCHEME_NTLM.equals( scheme ) && authenticationStrategy
							.supportsNtlm( ) );
		}
		
		return loginRequest;
	}
	
	// FIXME: Error handling
	protected IwaAuthenticationRequest buildAuthenticationRequest(
			ServletRequest request ) {
		String[] authzHeaderParts = extractAuthzHeaderParts( request );
		assert authzHeaderParts != null;
		
		IwaAuthenticationScheme scheme = IwaAuthenticationScheme
				.getScheme( authzHeaderParts[0] );
		
		return new IwaAuthenticationRequest(
				getConnectionId( request ),
				scheme,
				Base64.decode( authzHeaderParts[1] ) );
	}
	
	protected String getConnectionId( ServletRequest request ) {
		return request.getRemoteAddr( ) + ":" + request.getRemotePort( );
	}
	
	/**
	 * 
	 * 
	 * @param request
	 * @return
	 */
	String[] extractAuthzHeaderParts( ServletRequest request ) {
		HttpServletRequest httpRequest = WebUtils.toHttp( request );
		
		String authzHeader = httpRequest.getHeader( "Authorization" );
		if( authzHeader != null ) {
			String[] parts = authzHeader.split( " ", 2 );
			if( parts.length == 2 ) {
				return parts;
			}
		}
		
		return null;
	}
}
