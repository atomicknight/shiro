package org.apache.shiro.iwa.ntlm;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public final class NtlmConstants {
	public static final byte[] NTLMSSP_FINGERPRINT = "NTLMSSP\0".getBytes( );
	
	public static final String NTLMSSP_MECHANISM = "1.3.6.1.4.1.311.2.2.10";
	public static final Oid NTLMSSP_OID;
	static {
		try {
			NTLMSSP_OID = new Oid( NTLMSSP_MECHANISM );
		} catch( GSSException e ) {
			// Should never happen
			throw new IllegalStateException( e );
		}
	}
}
