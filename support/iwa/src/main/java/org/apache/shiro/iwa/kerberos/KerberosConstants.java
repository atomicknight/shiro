package org.apache.shiro.iwa.kerberos;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public final class KerberosConstants {
	public static final String KERBEROS_V5_MECHANISM = "1.2.840.113554.1.2.2";
	public static final Oid KERBEROS_V5_OID;
	static {
		try {
			KERBEROS_V5_OID = new Oid( KERBEROS_V5_MECHANISM );
		} catch( GSSException e ) {
			// Should never happen
			throw new IllegalStateException( e );
		}
	}
}
