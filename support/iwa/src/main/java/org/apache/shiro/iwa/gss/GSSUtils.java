package org.apache.shiro.iwa.gss;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;

public class GSSUtils {
	protected GSSUtils( ) {
		
	}
	
	public static String getMechanism( byte[] token )
			throws IllegalArgumentException {
		try {
			byte[] contents = cast(
					ASN1Primitive.fromByteArray( token ),
					DERApplicationSpecific.class ).getContents( );
			
			if( contents[0] != (byte)0x06 ) {
				throw new IllegalArgumentException(
						"Unable to parse GSS token: Expected OID, but found "
								+ contents[0] );
			}
			int oidLength = contents[1];
			byte[] oidElement = new byte[oidLength + 2];
			System.arraycopy( contents, 0, oidElement, 0, oidElement.length );
			return cast(
					ASN1Primitive.fromByteArray( oidElement ),
					DERObjectIdentifier.class ).getId( );
		} catch( IOException e ) {
			throw new IllegalArgumentException( "Unable to parse GSS token", e );
		}
	}
	
	protected static <T> T cast( ASN1Encodable object, Class<T> targetClass ) {
		if( !targetClass.isInstance( object ) ) {
			throw new IllegalArgumentException(
					"Unable to parse GSS token: Expected "
							+ targetClass.getSimpleName( ) + ", but found "
							+ object );
		}
		return targetClass.cast( object );
	}
}
