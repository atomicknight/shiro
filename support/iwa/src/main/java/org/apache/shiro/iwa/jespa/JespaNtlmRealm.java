package org.apache.shiro.iwa.jespa;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.iwa.ntlm.NtlmToken;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

public class JespaNtlmRealm extends AuthorizingRealm {
	private NtlmSecurityProviderFactory providerFactory;
	
	public JespaNtlmRealm( ) {
		providerFactory = new DefaultNtlmSecurityProviderFactory( );
	}
	
	public JespaNtlmRealm( NtlmSecurityProviderFactory providerFactory ) {
		this.providerFactory = providerFactory;
	}
	
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals ) {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token ) throws AuthenticationException {
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public Class<?> getAuthenticationTokenClass( ) {
		return NtlmToken.class;
	}
	
	@Override
	public final void setAuthenticationTokenClass(
			Class<? extends AuthenticationToken> authenticationTokenClass ) {
		throw new UnsupportedOperationException(
				"Cannot set authentication token class for class "
						+ getClass( ).getSimpleName( ) );
	}
	
	@Override
	public final boolean supports( AuthenticationToken token ) {
		return super.supports( token );
	}
}
