package org.apache.shiro.iwa.spnego;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERObjectIdentifier;

/**
 * Per RFC 4178.
 * 
 * @author Abraham Lin
 */
public final class NegTokenInit {
	private List<String> mechTypes = null;
	private byte[] mechToken = null;
	private byte[] mechListMIC = null;
	
	public NegTokenInit( byte[] token ) throws IllegalArgumentException {
		try {
			ASN1StreamParser parser = new ASN1StreamParser(
					new ByteArrayInputStream( cast(
							ASN1Primitive.fromByteArray( token ),
							DERApplicationSpecific.class ).getContents( ) ) );
			
			DERObjectIdentifier oid = cast(
					parser.readObject( ),
					DERObjectIdentifier.class );
			if( !SpnegoConstants.SPNEGO_MECHANISM.equals( oid.getId( ) ) ) {
				throw new IllegalArgumentException(
						"Unable to parse NegTokenInit: Illegal OID "
								+ oid.getId( ) );
			}
			
			ASN1Encodable[] objects = cast(
					cast( parser.readObject( ), ASN1TaggedObjectParser.class )
							.getObjectParser( 0, true )
							.toASN1Primitive( ),
					ASN1Sequence.class ).toArray( );
			for( ASN1Encodable object : objects ) {
				ASN1TaggedObject taggedObject = cast(
						object,
						ASN1TaggedObject.class );
				switch( taggedObject.getTagNo( ) ) {
					case 0:
						ASN1Sequence mechTypesSequence = cast(
								taggedObject.getObject( ),
								ASN1Sequence.class );
						mechTypes = new ArrayList<String>(
								mechTypesSequence.size( ) );
						for( ASN1Encodable mechType : mechTypesSequence
								.toArray( ) ) {
							mechTypes.add( cast(
									mechType,
									DERObjectIdentifier.class ).getId( ) );
						}
						break;
					case 1:
						// Ignore reqFlags
						break;
					case 2:
						mechToken = cast(
								taggedObject.getObject( ),
								ASN1OctetString.class ).getOctets( );
						break;
					case 3:
						mechListMIC = cast(
								taggedObject.getObject( ),
								ASN1OctetString.class ).getOctets( );
						break;
					default:
						throw new IllegalArgumentException(
								"Unable to parse NegTokenInit: Found illegal tag number "
										+ taggedObject.getTagNo( ) );
				}
			}
		} catch( IOException e ) {
			throw new IllegalArgumentException(
					"Unable to parse NegTokenInit",
					e );
		}
	}
	
	/**
	 * @return the mechTypes
	 */
	public List<String> getMechTypes( ) {
		return mechTypes;
	}
	
	/**
	 * @return the mechToken
	 */
	public byte[] getMechToken( ) {
		return mechToken;
	}
	
	/**
	 * @return the mechListMIC
	 */
	public byte[] getMechListMIC( ) {
		return mechListMIC;
	}
	
	private static <T> T cast( ASN1Encodable object, Class<T> targetClass ) {
		if( !targetClass.isInstance( object ) ) {
			throw new IllegalArgumentException(
					"Unable to parse NegTokenInit: Expected "
							+ targetClass.getSimpleName( ) + ", but found "
							+ object );
		}
		return targetClass.cast( object );
	}
}
