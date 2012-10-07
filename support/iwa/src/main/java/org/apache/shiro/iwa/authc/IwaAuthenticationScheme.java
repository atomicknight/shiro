package org.apache.shiro.iwa.authc;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public enum IwaAuthenticationScheme {
	SPNEGO( "Negotiate" ),
	NTLM( "NTLM" );
	
	private static final Map<String, IwaAuthenticationScheme> VALUES;
	static {
		Map<String, IwaAuthenticationScheme> values = new HashMap<String, IwaAuthenticationScheme>( );
		for( IwaAuthenticationScheme scheme : IwaAuthenticationScheme.values( ) ) {
			values.put( scheme.getValue( ), scheme );
		}
		VALUES = Collections.unmodifiableMap( values );
	}
	
	private final String value;
	
	private IwaAuthenticationScheme( String value ) {
		this.value = value;
	}
	
	/**
	 * @return the value
	 */
	public String getValue( ) {
		return value;
	}
	
	@Override
	public String toString( ) {
		return getValue( );
	}

	public static IwaAuthenticationScheme getScheme( String value ) {
		return VALUES.get( value );
	}
}