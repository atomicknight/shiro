package org.apache.shiro.iwa.jespa;

import java.util.HashMap;
import java.util.Map;

import jespa.ntlm.NtlmSecurityProvider;

public class DefaultNtlmSecurityProviderFactory implements
		NtlmSecurityProviderFactory {
	private Map<Object, Object> properties;
	
	public DefaultNtlmSecurityProviderFactory( ) {
		properties = new HashMap<Object, Object>( );
	}
	
	public DefaultNtlmSecurityProviderFactory( Map<Object, Object> properties ) {
		this.properties = properties;
	}
	
	@Override
	public NtlmSecurityProvider create( ) {
		return new NtlmSecurityProvider( properties );
	}
}
