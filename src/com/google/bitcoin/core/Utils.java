/**
 * Copyright 2011 Ken Burford
 * 
 * This file is part of the Bitventory Signing Applet.
 * 
 * The Bitventory Signing Applet is free software:
 * you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 * 
 * The Bitventory Signing Applet is distributed in the hope
 * that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with the Bitventory Signing Applet. 
 * If not, see <http://www.gnu.org/licenses/>.
**/

/**
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.core;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

/**
 * A collection of various utility methods that are helpful for working with the BitCoin protocol.
 * To enable debug logging from the library, run with -Dbitcoinj.logging=true on your command line.
 */
@SuppressWarnings({"SameParameterValue"})
public class Utils {
    // TODO: Replace this nanocoins business with something better.

    /**
     * How many "nanocoins" there are in a BitCoin.
     *
     * A nanocoin is the smallest unit that can be transferred using BitCoin.
     * The term nanocoin is very misleading, though, because there are only 100 million
     * of them in a coin (whereas one would expect 1 billion.
     */
    public static final BigInteger COIN = new BigInteger("100000000", 10);

    /**
     * How many "nanocoins" there are in 0.01 BitCoins.
     *
     * A nanocoin is the smallest unit that can be transferred using BitCoin.
     * The term nanocoin is very misleading, though, because there are only 100 million
     * of them in a coin (whereas one would expect 1 billion).
     */
    public static final BigInteger CENT = new BigInteger("1000000", 10);

    /** Convert an amount expressed in the way humans are used to into nanocoins. */
    public static BigInteger toNanoCoins(int coins, int cents) {
        assert cents < 100;
        BigInteger bi = BigInteger.valueOf(coins).multiply(COIN);
        bi = bi.add(BigInteger.valueOf(cents).multiply(CENT));
        return bi;
    }

    /**
     * Convert an amount expressed in the way humans are used to into nanocoins.<p>
     *
     * This takes string in a format understood by {@link BigDecimal#BigDecimal(String)},
     * for example "0", "1", "0.10", "1.23E3", "1234.5E-5".
     * 
     * @throws ArithmeticException if you try to specify fractional nanocoins
     **/
    public static BigInteger toNanoCoins(String coins){
        return new BigDecimal(coins).movePointRight(8).toBigIntegerExact();
    }

    public static void uint32ToByteArrayBE(long val, byte[] out, int offset) {
        out[offset + 0] = (byte) (0xFF & (val >> 24));
        out[offset + 1] = (byte) (0xFF & (val >> 16));
        out[offset + 2] = (byte) (0xFF & (val >>  8));
        out[offset + 3] = (byte) (0xFF & (val >>  0));      
    }

    public static void uint32ToByteArrayLE(long val, byte[] out, int offset) {
        out[offset + 0] = (byte) (0xFF & (val >>  0));
        out[offset + 1] = (byte) (0xFF & (val >>  8));
        out[offset + 2] = (byte) (0xFF & (val >> 16));
        out[offset + 3] = (byte) (0xFF & (val >> 24));      
    }
    
    public static void uint32ToByteStreamLE(long val, OutputStream stream) throws IOException {
        stream.write((int)(0xFF & (val >>  0)));
        stream.write((int)(0xFF & (val >>  8)));
        stream.write((int)(0xFF & (val >> 16)));
        stream.write((int)(0xFF & (val >> 24)));
    }
    
    public static void uint64ToByteStreamLE(BigInteger val, OutputStream stream) throws IOException {
        byte[] bytes = val.toByteArray();
        if (bytes.length > 8) { 
            throw new RuntimeException("Input too large to encode into a uint64");
        }
        bytes = reverseBytes(bytes);
        stream.write(bytes);
        if (bytes.length < 8) {
            for (int i = 0; i < 8 - bytes.length; i++)
                stream.write(0);
        }
    }

    /**
     * See {@link Utils#doubleDigest(byte[],int,int)}.
     */
    public static byte[] doubleDigest(byte[] input) {
        return doubleDigest(input, 0, input.length);
    }

    /**
     * Calculates the SHA-256 hash of the given byte range, and then hashes the resulting hash again. This is
     * standard procedure in BitCoin. The resulting hash is in big endian form.
     */
    public static byte[] doubleDigest(byte[] input, int offset, int length) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(input, offset, length);
            byte[] first = digest.digest();
            return digest.digest(first);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /**
     * Calculates SHA256(SHA256(byte range 1 + byte range 2)).
     */
    public static byte[] doubleDigestTwoBuffers(byte[] input1, int offset1, int length1,
                                                byte[] input2, int offset2, int length2) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(input1, offset1, length1);
            digest.update(input2, offset2, length2);
            byte[] first = digest.digest();
            return digest.digest(first);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Work around lack of unsigned types in Java. */
    public static boolean isLessThanUnsigned(long n1, long n2) { 
        return (n1 < n2) ^ ((n1 < 0) != (n2 < 0));
    }

    /** Returns the given byte array hex encoded. */
    public static String bytesToHexString(byte[] bytes) {
        StringBuffer buf = new StringBuffer(bytes.length * 2);
        for (byte b : bytes) {
            String s = Integer.toString(0xFF & b, 16);
            if (s.length() < 2)
                buf.append('0');
            buf.append(s);
        }
        return buf.toString();
    }
    

    /** Returns a copy of the given byte array in reverse order. */
    public static byte[] reverseBytes(byte[] bytes) {
        // We could use the XOR trick here but it's easier to understand if we don't. If we find this is really a
        // performance issue the matter can be revisited.
        byte[] buf = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++)
            buf[i] = bytes[bytes.length - 1 - i];
        return buf;
    }

    public static long readUint32(byte[] bytes, int offset) {
        return ((bytes[offset++] & 0xFFL) <<  0) |
               ((bytes[offset++] & 0xFFL) <<  8) |
               ((bytes[offset++] & 0xFFL) << 16) |
               ((bytes[offset] & 0xFFL) << 24);
    }
    
    public static long readUint32BE(byte[] bytes, int offset) {
        return ((bytes[offset + 0] & 0xFFL) << 24) |
               ((bytes[offset + 1] & 0xFFL) << 16) |
               ((bytes[offset + 2] & 0xFFL) <<  8) |
               ((bytes[offset + 3] & 0xFFL) <<  0);
    }
    
    public static int readUint16BE(byte[] bytes, int offset) {
	    return ((bytes[offset] & 0xff) << 8) | bytes[offset + 1] & 0xff;
    }

    /**
     * Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
     */
    public static byte[] sha256hash160(byte[] input) {
        try {
            byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(input);
            RIPEMD160Digest digest = new RIPEMD160Digest();
            digest.update(sha256, 0, sha256.length);
            byte[] out = new byte[20];
            digest.doFinal(out, 0);
            return out;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Returns the given value in nanocoins as a 0.12 type string. */
    public static String bitcoinValueToFriendlyString(BigInteger value) {
        boolean negative = value.compareTo(BigInteger.ZERO) < 0;
        if (negative)
            value = value.negate();
        BigInteger coins = value.divide(COIN);
        BigInteger cents = value.remainder(COIN);
        return String.format("%s%d.%05d", negative ? "-" : "", coins.intValue(), cents.intValue() / 1000);
    }
    
    /**
     * MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function. They consist of
     * a 4 byte big endian length field, followed by the stated number of bytes representing
     * the number in big endian format.
     */
    static BigInteger decodeMPI(byte[] mpi) {
        int length = (int) readUint32BE(mpi, 0);
        byte[] buf = new byte[length];
        System.arraycopy(mpi, 4, buf, 0, length);
        return new BigInteger(buf);
    }

    // The representation of nBits uses another home-brew encoding, as a way to represent a large
    // hash value in only 32 bits.
    static BigInteger decodeCompactBits(long compact) {
        int size = ((int)(compact >> 24)) & 0xFF;
        byte[] bytes = new byte[4 + size];
        bytes[3] = (byte) size;
        if (size >= 1) bytes[4] = (byte) ((compact >> 16) & 0xFF);
        if (size >= 2) bytes[5] = (byte) ((compact >>  8) & 0xFF);
        if (size >= 3) bytes[6] = (byte) ((compact >>  0) & 0xFF);
        return decodeMPI(bytes);
    }

    /** If non-null, overrides the return value of now(). */
    public static Date mockTime;

    /** Advances (or rewinds) the mock clock by the given number of seconds. */
    public static Date rollMockClock(int seconds) {
        if (mockTime == null)
            mockTime = new Date();
        mockTime = new Date(mockTime.getTime() + (seconds * 1000));
        return mockTime;
    }

    /** Returns the current time, or a mocked out equivalent. */
    public static Date now() {
        if (mockTime != null)
            return mockTime;
        else
            return new Date();
    }
}
