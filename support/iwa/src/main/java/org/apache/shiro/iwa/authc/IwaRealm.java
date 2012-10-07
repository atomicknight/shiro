package org.apache.shiro.iwa.authc;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;

public class IwaRealm extends AuthenticatingRealm {
	
	@Override
	protected final AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token ) throws AuthenticationException {
		SimplePrincipalCollection principals = new SimplePrincipalCollection( );
		principals.add( token.getPrincipal( ), getName( ) );
		return new SimpleAuthenticationInfo( principals, token.getCredentials( ) );
	}

	@Override
	public final Class<?> getAuthenticationTokenClass( ) {
		return AuthenticatedIwaToken.class;
	}

	@Override
	public final void setAuthenticationTokenClass(
			Class<? extends AuthenticationToken> authenticationTokenClass ) {
		throw new UnsupportedOperationException(
				"AuthenticationToken class cannot be set for IwaRealm" );
	}

	@Override
	public final boolean supports( AuthenticationToken token ) {
		return super.supports( token );
	}
}
