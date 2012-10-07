package org.apache.shiro.iwa.jespa;

import jespa.ntlm.NtlmSecurityProvider;

public interface NtlmSecurityProviderFactory {
	/**
	 * 
	 * 
	 * @return
	 */
	NtlmSecurityProvider create( );
}
