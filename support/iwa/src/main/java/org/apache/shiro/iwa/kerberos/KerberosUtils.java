package org.apache.shiro.iwa.kerberos;

import java.io.IOException;

import org.apache.shiro.iwa.gss.GSSUtils;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;

public final class KerberosUtils extends GSSUtils {
	protected KerberosUtils( ) {
		
	}
	
	/**
	 * Unwraps a GSS token
	 * 
	 * @param token
	 * @return
	 * @throws IllegalArgumentException
	 *             TODO
	 */
	public static byte[] unwrap( byte[] token ) throws IllegalArgumentException {
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
			DERObjectIdentifier oid = cast(
					ASN1Primitive.fromByteArray( oidElement ),
					DERObjectIdentifier.class );
			if( !KerberosConstants.KERBEROS_V5_MECHANISM.equals( oid.getId( ) ) ) {
				throw new IllegalArgumentException(
						"Unable to parse GSS token: Illegal OID " + oid.getId( ) );
			}
			
			// Search for the closest (constructed) application element
			int index = oidElement.length;
			while( index < contents.length ) {
				if( ( contents[index] & BERTags.APPLICATION ) == 0x1 ) {
					byte[] unwrappedToken = new byte[contents.length - index];
					System.arraycopy(
							contents,
							index,
							unwrappedToken,
							0,
							unwrappedToken.length );
					return unwrappedToken;
				}
				index++;
			}
			throw new IllegalArgumentException(
					"Unable to parse GSS token: No Kerberos token found" );
		} catch( IOException e ) {
			throw new IllegalArgumentException( "Unable to parse GSS token", e );
		} catch( IndexOutOfBoundsException e ) {
			throw new IllegalArgumentException(
					"Unable to parse GSS token: Unexpected end of token",
					e );
		}
	}
}
