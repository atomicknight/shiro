/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.authc.credential;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.codec.Base64;
import org.jsecurity.codec.Hex;
import org.jsecurity.crypto.hash.AbstractHash;
import org.jsecurity.crypto.hash.Hash;

/**
 * A <tt>HashedCredentialMatcher</tt> provides support for hashing of supplied <tt>AuthenticationToken</tt> credentials
 * before being compared to those in the <tt>Account</tt> from the data store.
 *
 * <p>Credential hashing is one of the most common security techniques when safeguarding a user's private credentials
 * (passwords, keys, etc).  Most developers never want to store their users' credentials in plain form, viewable by
 * anyone, so they often hash the users' credentials before they are saved in the data store.</p>
 *
 * <p>This class (and its subclasses) function as follows:</p>
 *
 * <p>It first hashes the <tt>AuthenticationToken</tt> credentials supplied by the user during their login.  It then
 * compares this hashed value directly with the <tt>Account</tt> credentials stored in the system.  The stored account
 * credentials are expected to already be in hashed form.  If these two values are equal, the submitted credentials
 * match.</p>
 *
 * <h3>Salting and Multiple Hash Iterations</h3>
 *
 * <p>Because simple hashing is sometimes not good enough for many applications, this class also supports 'salting'
 * and multiple hash iterations.  Please read this excellent
 * <a href="http://www.owasp.org/index.php/Hashing_Java" _target="blank">Hashing Java article</a> to learn about
 * salting and multiple iterations and why you might want to use them. (Note of sections 5
 * &quot;Why add salt?&quot; and 6 "Hardening against the attacker's attack").
 *
 * <p>We should also note here that all of JSecurity's Hash implementations (for example,
 * {@link org.jsecurity.crypto.hash.Md5Hash Md5Hash}, {@link org.jsecurity.crypto.hash.ShaHash ShaHash}, etc)
 * support salting and multiple hash iterations via overloaded constructors.</p>
 *
 * <h4>Salting</h4>
 *
 * <p>Salting of the authentication token's credentials hash is disabled by default, but you may enable it by setting
 * {@link #setHashSalted hashSalted} to
 * <tt>true</tt>.  If you do enable it, the value used to salt the hash will be
 * obtained from {@link #getSalt(AuthenticationToken) getSalt(authenticationToken}.
 *
 * <p>The default <tt>getSalt</tt> implementation merely returns
 * <code>token.getPrincipal()</code>, effectively using the user's identity as the salt, a most common technique.  If
 * you wish to provide the authentication token's salt another way, you may override this <tt>getSalt</tt> method.
 *
 * <h4>Multiple Hash Iterations</h4>
 *
 * <p>If you hash your users' credentials multiple times before persisting to the data store, you will also need to
 * set this class's {@link #setHashIterations(int) hashIterations} property.</p>
 *
 * @see org.jsecurity.crypto.hash.Md5Hash
 * @see org.jsecurity.crypto.hash.ShaHash
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class HashedCredentialsMatcher extends SimpleCredentialsMatcher {

    private boolean storedCredentialsHexEncoded = true; //false means base64 encoded
    private boolean hashSalted = false;
    private int hashIterations = 1;

    /**
     * Returns <tt>true</tt> if the system's stored credential hash is Hex encoded, <tt>false</tt> if it
     * is Base64 encoded.
     *
     * <p>Default value is <tt>true</tt> for convenience - all of JSecurity's {@link Hash Hash#toString()}
     * implementations return Hex encoded values by default, making this class's use with those implementations 
     * easier.</p>
     *
     * @return <tt>true</tt> if the system's stored credential hash is Hex encoded, <tt>false</tt> if it
     *         is Base64 encoded.  Default is <tt>true</tt>
     */
    public boolean isStoredCredentialsHexEncoded() {
        return storedCredentialsHexEncoded;
    }

    /**
     * Sets the indicator if this system's stored credential hash is Hex encoded or not.
     *
     * <p>A value of <tt>true</tt> will cause this class to decode the system credential from Hex, a
     * value of <tt>false</tt> will cause this class to decode the system credential from Base64.</p>
     *
     * <p>Unless overridden via this method, the default value is <tt>true</tt> for convenience - all of JSecurity's
     * {@link Hash Hash#toString()} implementations return Hex encoded values by default, making this class's use with
     * those implementations easier.</p>.
     *
     * @param storedCredentialsHexEncoded the indicator if this system's stored credential hash is Hex
     *                                    encoded or not ('not' automatically implying it is Base64 encoded).
     */
    public void setStoredCredentialsHexEncoded(boolean storedCredentialsHexEncoded) {
        this.storedCredentialsHexEncoded = storedCredentialsHexEncoded;
    }

    /**
     * Returns <tt>true</tt> if a submitted <tt>AuthenticationToken</tt>'s credentials should be salted when hashing,
     * <tt>false</tt> if it should not be salted.
     *
     * <p>If enabled, the salt used will be obtained via the {@link #getSalt(AuthenticationToken) getSalt} method.
     *
     * @return <tt>true</tt> if a submitted <tt>AuthenticationToken</tt>'s credentials should be salted when hashing,
     * <tt>false</tt> if it should not be salted.
     */
    public boolean isHashSalted() {
        return hashSalted;
    }

    /**
     * Sets whether or not to salt a submitted <tt>AuthenticationToken</tt>'s credentials when hashing.
     * 
     * <p>If enabled, the salt used will be obtained via the {@link #getSalt(AuthenticationToken) getSalt} method.
     *
     * @param hashSalted whether or not to salt a submitted <tt>AuthenticationToken</tt>'s credentials when hashing.
     */
    public void setHashSalted(boolean hashSalted) {
        this.hashSalted = hashSalted;
    }

    /**
     * Returns the number of times a submitted <tt>AuthenticationToken</tt>'s credentials will be hashed before
     * comparing to the credentials stored in the system.
     *
     * <p>Unless overridden, the default value is <tt>1</tt>, meaning a normal hash execution will occur.
     *
     * @return the number of times a submitted <tt>AuthenticationToken</tt>'s credentials will be hashed before
     * comparing to the credentials stored in the system.
     */
    public int getHashIterations() {
        return hashIterations;
    }

    /**
     * Sets the number of times a submitted <tt>AuthenticationToken</tt>'s credentials will be hashed before comparing
     * to the credentials stored in the system.
     *
     * <p>Unless overridden, the default value is <tt>1</tt>, meaning a normal single hash execution will occur.
     *
     * <p>If this argument is less than 1 (i.e. 0 or negative), the default value of 1 is applied.  There must always be
     * at least 1 hash iteration (otherwise there would be no hash).
     *
     * @param hashIterations the number of times to hash a submitted <tt>AuthenticationToken</tt>'s credentials.
     */
    public void setHashIterations(int hashIterations) {
        if ( hashIterations < 1 ) {
            this.hashIterations = 1;
        } else {
            this.hashIterations = hashIterations;
        }
    }

    /**
     * Returns a salt value used to hash the token's credentials.
     *
     * <p>This default implementation merely returns <code>token.getPrincipal()</code>, effectively using the user's
     * identity (username, user id, etc) as the salt, a most common technique.  If you wish to provide the
     * authentication token's salt another way, you may override this method.
     * @param token the AuthenticationToken submitted during the authentication attempt.
     * @return a salt value to use to hash the authentication token's credentials.
     */
    protected Object getSalt( AuthenticationToken token ) {
        return token.getPrincipal();
    }

    /**
     * As this is a HashedCredentialMatcher, this method overrides the parent by returning a hashed value
     * of the submitted token's credentials.  Based on this class's configuration, the return value may be salted and/or
     * hashed multiple times (see the class-level JavaDoc for more information on salting and
     * multiple hash iterations).
     *
     * @param token the authentication token submitted during the authentication attempt.
     * @return the hashed value of the authentication token's credentials.
     */
    protected Object getCredentials(AuthenticationToken token) {
        Object salt = isHashSalted() ? getSalt( token ) : null;
        return getProvidedCredentialsHash(token.getCredentials(), salt, getHashIterations() );
    }

    /**
     * Returns a {@link Hash Hash} instance representing the already-hashed Account credentials stored in the system.
     *
     * <p>This method reconstructs a {@link Hash Hash} instance based on a <code>account.getCredentials</code> call,
     * but it does <em>not</em> hash that value - it is expected that method call will return an already-hashed value.
     *
     * <p>This implementation's reconstruction effort functions as follows:
     *
     * <ul>
     * <li>If <code>account.getCredentials()</code> is a byte array, just set that byte array directly on
     * the <tt>Hash</tt> implementation and return it.</li>
     * <li>If <code>account.getCredentials()</code> is <em>not</em> a byte array, convert it to a byte array via the
     * {@link #toBytes toBytes} method, and then check for encoding:
     * <ol><li>If {@link #storedCredentialsHexEncoded storedCredentialsHexEncoded}, Hex decode that byte array, otherwise
     *         Base64 decode the byte array</li>
     *     <li>Set the decoded bytes directly on the <tt>Hash</tt> implementation and return it.</li></ol>
     * </li>
     * </ul>
     *
     * @param account the Account from which to retrive the credentials which assumed to be in already-hashed form.
     * @return a {@link Hash Hash} instance representing the given Account's stored credentials.
     */
    protected Object getCredentials(Account account) {
        Object credentials = account.getCredentials();

        //assume stored credential is already hashed:
        AbstractHash hash = newHashInstance();

        //apply stored credentials to this Hash instance
        byte[] storedBytes = toBytes(credentials);

        if (!(credentials instanceof byte[])) {
            //method argument came in as a char[] or String, so
            //we need to do text decoding first:
            if (isStoredCredentialsHexEncoded()) {
                storedBytes = Hex.decode( storedBytes );
            } else {
                storedBytes = Base64.decodeBase64( storedBytes );
            }
        }
        hash.setBytes( storedBytes );
        return hash;
    }

    /**
     * Hashes the provided credentials a total of <tt>hashIterations</tt> times, using the given salt.  The hash
     * implementation/algorithm used is left to subclasses.
     *
     * @param credential the submitted authentication token's credentials to hash
     * @param salt the value to salt the hash, or <tt>null</tt> if a salt will not be used.
     * @param hashIterations the number of times to hash the credentials.  At least one hash will always occur though,
     * even if this argument is 0 or negative.
     * @return the hashed value of the provided credentials, according to the specified salt and hash iterations.
     */
    protected abstract Hash getProvidedCredentialsHash(Object credential, Object salt, int hashIterations );

    /**
     * Returns a new, <em>uninitialized</em> instance, without its byte array set.  Used as a utility method in the
     * {@link #getCredentials(Account) getCredentials(Account)} implementation.
     *
     * @return a new, <em>uninitialized</em> instance, without its byte array set.
     */
    protected abstract AbstractHash newHashInstance();

}
