package org.apache.shiro.iwa.authc;

import org.apache.shiro.authc.AuthenticationToken;

public final class AuthenticatedIwaToken implements AuthenticationToken {
	private static final long serialVersionUID = 1L;

	private final Object principal;
	
	public AuthenticatedIwaToken( Object principal ) {
		this.principal = principal;
	}
	
	public Object getPrincipal( ) {
		return principal;
	}
	
	public Object getCredentials( ) {
		return null;
	}
}
