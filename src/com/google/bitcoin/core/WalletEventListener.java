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

import java.math.BigInteger;

/**
 * Implementing WalletEventListener allows you to learn when the contents of the wallet changes due to
 * receiving money or a block chain re-organize. Methods are called with the event listener object locked so your
 * implementation does not have to be thread safe. It may be convenient to derive from
 * {@link AbstractWalletEventListener} instead.
 */
public interface WalletEventListener {
    /**
     * This is called on a Peer thread when a block is received that sends some coins to you. Note that this will
     * also be called when downloading the block chain as the wallet balance catches up so if you don't want that
     * register the event listener after the chain is downloaded. It's safe to use methods of wallet during the
     * execution of this callback.
     *
     * @param wallet The wallet object that received the coins/
     * @param tx The transaction which sent us the coins.
     * @param prevBalance Balance before the coins were received.
     * @param newBalance Current balance of the wallet.
     */
    void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance);

    /**
     * This is called on a Peer thread when a block is received that triggers a block chain re-organization.<p>
     *
     * A re-organize means that the consensus (chain) of the network has diverged and now changed from what we
     * believed it was previously. Usually this won't matter because the new consensus will include all our old
     * transactions assuming we are playing by the rules. However it's theoretically possible for our balance to
     * change in arbitrary ways, most likely, we could lose some money we thought we had.<p>
     *
     * It is safe to use methods of wallet whilst inside this callback.
     *
     * TODO: Finish this interface.
     */
    void onReorganize(Wallet wallet);

    /**
     * This is called on a Peer thread when a transaction becomes <i>dead</i>. A dead transaction is one that has
     * been overridden by a double spend from the network and so will never confirm no matter how long you wait.<p>
     *
     * A dead transaction can occur if somebody is attacking the network, or by accident if keys are being shared.
     * You can use this event handler to inform the user of the situation. A dead spend will show up in the BitCoin
     * C++ client of the recipient as 0/unconfirmed forever, so if it was used to purchase something,
     * the user needs to know their goods will never arrive.
     *
     * @param deadTx The transaction that is newly dead.
     * @param replacementTx The transaction that killed it.
     */
    void onDeadTransaction(Wallet wallet, Transaction deadTx, Transaction replacementTx);
}
