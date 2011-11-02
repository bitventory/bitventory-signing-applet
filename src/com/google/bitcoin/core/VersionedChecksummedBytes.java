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

import java.util.Arrays;

/**
 * <p>In Bitcoin the following format is often used to represent some type of key:</p>
 *
 * <pre>[one version byte] [data bytes] [4 checksum bytes]</pre>
 *
 * <p>and the result is then Base58 encoded. This format is used for addresses, and private keys exported using the
 * dumpprivkey command.</p>
 */
public class VersionedChecksummedBytes {
    protected int version;
    protected byte[] bytes;

    protected VersionedChecksummedBytes(String encoded) throws AddressFormatException {
        byte[] tmp = Base58.decodeChecked(encoded);
        version = tmp[0] & 0xFF;
        bytes = new byte[tmp.length - 1];
        System.arraycopy(tmp, 1, bytes, 0, tmp.length - 1);
    }

    protected VersionedChecksummedBytes(int version, byte[] bytes) {
        assert version < 256 && version >= 0;
        this.version = version;
        this.bytes = bytes;
    }

    @Override
    public String toString() {
        // A stringified buffer is:
        //   1 byte version + data bytes + 4 bytes check code (a truncated hash)
        byte[] addressBytes = new byte[1 + bytes.length + 4];
        addressBytes[0] = (byte)version;
        System.arraycopy(bytes, 0, addressBytes, 1, bytes.length);
        byte[] check = Utils.doubleDigest(addressBytes, 0, bytes.length + 1);
        System.arraycopy(check, 0, addressBytes, bytes.length + 1, 4);
        return Base58.encode(addressBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof VersionedChecksummedBytes)) return false;
        VersionedChecksummedBytes vcb = (VersionedChecksummedBytes) o;
        return Arrays.equals(vcb.bytes, bytes);
    }

    /**
     * Returns the "version" or "header" byte: the first byte of the data. This is used to disambiguate what the
     * contents apply to, for example, which network the key or address is valid on.
     * @return A positive number between 0 and 255.
     */
    public int getVersion() {
        return version;
    }
}
