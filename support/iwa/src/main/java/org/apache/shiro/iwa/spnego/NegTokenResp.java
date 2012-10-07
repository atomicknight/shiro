package org.apache.shiro.iwa.spnego;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * Per RFC 4178.
 * 
 * @author Abraham Lin
 */
public final class NegTokenResp {
	private NegState negState = null;
	private String supportedMech = null;
	private byte[] responseToken = null;
	private byte[] mechListMIC = null;
	
	public NegTokenResp( NegState negState, String supportedMech,
			byte[] responseToken, byte[] mechListMIC ) {
		this.negState = negState;
		this.supportedMech = supportedMech;
		this.responseToken = responseToken;
		this.mechListMIC = mechListMIC;
	}
	
	public NegTokenResp( byte[] token ) throws IllegalArgumentException {
		try {
			ASN1Encodable[] objects = cast(
					cast(
							ASN1Primitive.fromByteArray( token ),
							ASN1TaggedObject.class ).getObject( ),
					ASN1Sequence.class ).toArray( );
			for( ASN1Encodable object : objects ) {
				ASN1TaggedObject taggedObject = cast(
						object,
						ASN1TaggedObject.class );
				switch( taggedObject.getTagNo( ) ) {
					case 0:
						negState = NegState.forValue( DEREnumerated
								.getInstance( taggedObject, true )
								.getValue( )
								.intValue( ) );
						break;
					case 1:
						supportedMech = cast(
								taggedObject.getObject( ),
								DERObjectIdentifier.class ).getId( );
						break;
					case 2:
						responseToken = cast(
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
								"Unable to parse NegTokenResp: Unexpected tag number "
										+ taggedObject.getTagNo( ) );
				}
			}
		} catch( IOException e ) {
			throw new IllegalArgumentException(
					"Unable to parse NegTokenResp",
					e );
		}
	}
	
	/**
	 * @return the negState
	 */
	public NegState getNegState( ) {
		return negState;
	}
	
	/**
	 * @return the supportedMech
	 */
	public String getSupportedMech( ) {
		return supportedMech;
	}
	
	/**
	 * @return the responseToken
	 */
	public byte[] getResponseToken( ) {
		return responseToken;
	}
	
	/**
	 * @return the mechListMIC
	 */
	public byte[] getMechListMIC( ) {
		return mechListMIC;
	}
	
	public byte[] toByteArray( ) {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream( );
		DERSequenceGenerator sequenceGenerator = null;
		try {
			sequenceGenerator = new DERSequenceGenerator( byteStream, 1, true );
			if( negState != null ) {
				sequenceGenerator.addObject( new DERTaggedObject(
						true,
						0,
						new DEREnumerated( negState.getValue( ) ) ) );
			}
			if( supportedMech != null ) {
				sequenceGenerator.addObject( new DERTaggedObject(
						true,
						1,
						new DERObjectIdentifier( supportedMech ) ) );
			}
			if( responseToken != null ) {
				sequenceGenerator.addObject( new DERTaggedObject(
						true,
						2,
						new DEROctetString( responseToken ) ) );
			}
			if( mechListMIC != null ) {
				sequenceGenerator.addObject( new DERTaggedObject(
						true,
						3,
						new DEROctetString( mechListMIC ) ) );
			}
		} catch( IOException e ) {
			// Should never happen
			throw new IllegalStateException(
					"Unable to serialize NegTokenResp",
					e );
		} finally {
			if( sequenceGenerator != null ) {
				try {
					sequenceGenerator.close( );
				} catch( IOException e ) {
					// Should never happen
					throw new IllegalStateException(
							"Unable to serialize NegTokenResp",
							e );
				}
			}
		}
		
		return byteStream.toByteArray( );
	}
	
	private static <T> T cast( ASN1Encodable object, Class<T> targetClass ) {
		if( !targetClass.isInstance( object ) ) {
			throw new IllegalArgumentException(
					"Unable to parse NegTokenResp: Expected "
							+ targetClass.getSimpleName( ) + ", but found "
							+ object );
		}
		return targetClass.cast( object );
	}
	
	public static enum NegState {
		ACCEPT_COMPLETED( 0 ),
		ACCEPT_INCOMPLETE( 1 ),
		REJECT( 2 ),
		REQUEST_MIC( 3 );
		
		private static final Map<Integer, NegState> STATES;
		static {
			Map<Integer, NegState> states = new HashMap<Integer, NegState>( );
			for( NegState state : NegState.values( ) ) {
				states.put( state.getValue( ), state );
			}
			STATES = Collections.unmodifiableMap( states );
		}
		
		private final int value;
		
		/**
		 * Constructs a {@code NegState} with the specified numerical value.
		 * 
		 * @param value
		 *            the value
		 */
		private NegState( int value ) {
			this.value = value;
		}
		
		/**
		 * Returns the numerical value of this state.
		 * 
		 * @return the value
		 */
		public int getValue( ) {
			return value;
		}
		
		public static NegState forValue( int value ) {
			return STATES.get( value );
		}
	}
}
