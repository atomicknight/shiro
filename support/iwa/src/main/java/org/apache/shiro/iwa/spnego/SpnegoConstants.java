package org.apache.shiro.iwa.spnego;

import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public final class SpnegoConstants {
	public static final String SPNEGO_MECHANISM = "1.3.6.1.5.5.2";
	public static final Oid SPNEGO_OID;
	static {
		try {
			SPNEGO_OID = new Oid( SPNEGO_MECHANISM );
		} catch( GSSException e ) {
			// Should never happen
			throw new IllegalStateException( e );
		}
	}
}
