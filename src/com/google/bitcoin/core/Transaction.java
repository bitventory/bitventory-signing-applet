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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.google.bitcoin.core.Utils.*;

/**
 * A transaction represents the movement of coins from some addresses to some other addresses. It can also represent
 * the minting of new coins. A Transaction object corresponds to the equivalent in the BitCoin C++ implementation.<p>
 *
 * It implements TWO serialization protocols - the BitCoin proprietary format which is identical to the C++
 * implementation and is used for reading/writing transactions to the wire and for hashing. It also implements Java
 * serialization which is used for the wallet. This allows us to easily add extra fields used for our own accounting
 * or UI purposes.
 */
public class Transaction extends Message implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(Transaction.class);
    private static final long serialVersionUID = -8567546957352643140L;
    
    // The key indices used to build this transaction
    public int[] keyIndices = null;
    
    // These are serialized in both bitcoin and java serialization.
    long version;
    ArrayList<TransactionInput> inputs;
    ArrayList<TransactionOutput> outputs;
    long lockTime;
    
    BigInteger fee;

    // This is only stored in Java serialization. It records which blocks (and their height + work) the transaction
    // has been included in. For most transactions this set will have a single member. In the case of a chain split a
    // transaction may appear in multiple blocks but only one of them is part of the best chain. It's not valid to
    // have an identical transaction appear in two blocks in the same chain but this invariant is expensive to check,
    // so it's not directly enforced anywhere.
    //
    // If this transaction is not stored in the wallet, appearsIn is null.
    Set<StoredBlock> appearsIn;

    // Stored only in Java serialization. This is either the time the transaction was broadcast as measured from the
    // local clock, or the time from the block in which it was included. Note that this can be changed by re-orgs so
    // the wallet may update this field. Old serialized transactions don't have this field, thus null is valid.
    // It is used for returning an ordered list of transactions from a wallet, which is helpful for presenting to
    // users.
    Date updatedAt;

    // This is an in memory helper only.
    transient Sha256Hash hash;

    Transaction(NetworkParameters params) {
        super(params);
        version = 1;
        inputs = new ArrayList<TransactionInput>();
        outputs = new ArrayList<TransactionOutput>();
        // We don't initialize appearsIn deliberately as it's only useful for transactions stored in the wallet.
    }

    /**
     * Creates a transaction from the given serialized bytes, eg, from a block or a tx network message.
     */
    public Transaction(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes, 0);
    }

    /**
     * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
     */
    public Transaction(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
        super(params, payload, offset);
        // inputs/outputs will be created in parse()
    }

    /**
     * Returns a read-only list of the inputs of this transaction.
     */
    public List<TransactionInput> getInputs() {
        return Collections.unmodifiableList(inputs);
    }
    
    public List<TransactionOutput> getOutputs() {
    	return Collections.unmodifiableList(outputs);
    }
    
    public BigInteger getCoinsOut() {
    	List<TransactionOutput> outs = getOutputs();
    	BigInteger total = BigInteger.ZERO;
    	for (TransactionOutput out : outs) {
    		total = total.add(out.getValue());
    	}
    	return total;
    } // getCoinsOut
    
    public void setFeeValue(BigInteger fee) {
    	this.fee = fee;
    } // setFeeValue
    
    public BigInteger getFeeValue() {
    	return this.fee;
    } // getFeeValue
    
    /**
     * Get the newest block containing this transaction.
     * 
     * @return	Block containing this transaction.
     */
    public StoredBlock getBlock() {
    	log.error("getBlock for: " + hash);
    	if (appearsIn == null) return null;
    	Iterator<StoredBlock> i = appearsIn.iterator();
    	if (i == null) return null; // Patch for when this tx isn't in a block
    	StoredBlock newest = null;
    	long time = 0;
    	while (i.hasNext()) {
    		StoredBlock block = i.next();
    		long now = block.getHeader().getTimeSeconds();
    		if (now > time) {
    			time = now;
    			newest = block;
    		}
    	} // while
    	return newest;
    } // getBlock
    
    /**
     * Returns the transaction hash as you see them in the block explorer.
     */
    public Sha256Hash getHash() {
        if (hash == null) {
            byte[] bits = bitcoinSerialize();
            hash = new Sha256Hash(reverseBytes(doubleDigest(bits)));
        }
        return hash;
    }

    public String getHashAsString() {
        return getHash().toString();
    }

    /**
     * Calculates the sum of the outputs that are sending coins to a key in the wallet. The flag controls whether to
     * include spent outputs or not.
     */
    BigInteger getValueSentToMe(Wallet wallet, boolean includeSpent) {
        // This is tested in WalletTest.
        BigInteger v = BigInteger.ZERO;
        for (TransactionOutput o : outputs) {
            if (!o.isMine(wallet)) continue;
            if (!includeSpent && !o.isAvailableForSpending()) continue;
            v = v.add(o.getValue());
        }
        return v;
    }

    /** Calculates the sum of the outputs that are sending coins to a key in the wallet. */
    public BigInteger getValueSentToMe(Wallet wallet) {
        return getValueSentToMe(wallet, true);
    }

    /**
     * Returns a set of blocks which contain the transaction, or null if this transaction doesn't have that data
     * because it's not stored in the wallet or because it has never appeared in a block.
     */
    Set<StoredBlock> getAppearsIn() {
        return appearsIn;
    }

    /**
     * Adds the given block to the internal serializable set of blocks in which this transaction appears. This is
     * used by the wallet to ensure transactions that appear on side chains are recorded properly even though the
     * block stores do not save the transaction data at all.
     *
     * @param block The {@link StoredBlock} in which the transaction has appeared.
     * @param bestChain whether to set the updatedAt timestamp from the block header (only if not already set)
     */
    void addBlockAppearance(StoredBlock block, boolean bestChain) {
        if (bestChain && updatedAt == null) {
            updatedAt = new Date(block.getHeader().getTimeSeconds() * 1000);
        }
        if (appearsIn == null) {
            appearsIn = new HashSet<StoredBlock>();
        }
        appearsIn.add(block);
    }

    /**
     * Calculates the sum of the inputs that are spending coins with keys in the wallet. This requires the
     * transactions sending coins to those keys to be in the wallet. This method will not attempt to download the
     * blocks containing the input transactions if the key is in the wallet but the transactions are not.
     *
     * @return sum in nanocoins.
     */
    public BigInteger getValueSentFromMe(Wallet wallet) throws ScriptException {
        // This is tested in WalletTest.
        BigInteger v = BigInteger.ZERO;
        for (TransactionInput input : inputs) {
            // This input is taking value from an transaction in our wallet. To discover the value,
            // we must find the connected transaction.
            TransactionOutput connected = input.getConnectedOutput(wallet.unspent);
            if (connected == null)
                connected = input.getConnectedOutput(wallet.spent);
            if (connected == null)
                connected = input.getConnectedOutput(wallet.pending);
            if (connected == null)
                continue;
            // The connected output may be the change to the sender of a previous input sent to this wallet. In this
            // case we ignore it.
            if (!connected.isMine(wallet))
                continue;
            v = v.add(connected.getValue());
        }
        return v;
    }

    boolean disconnectInputs() {
        boolean disconnected = false;
        for (TransactionInput input : inputs) {
            disconnected |= input.disconnect();
        }
        return disconnected;
    }

    /**
     * Connects all inputs using the provided transactions. If any input cannot be connected returns that input or
     * null on success.
     */
    TransactionInput connectForReorganize(Map<Sha256Hash, Transaction> transactions) {
        for (TransactionInput input : inputs) {
            // Coinbase transactions, by definition, do not have connectable inputs.
            if (input.isCoinBase()) continue;
            TransactionInput.ConnectionResult result = input.connect(transactions, false);
            // Connected to another tx in the wallet?
            if (result == TransactionInput.ConnectionResult.SUCCESS)
                continue;
            // The input doesn't exist in the wallet, eg because it belongs to somebody else (inbound spend).
            if (result == TransactionInput.ConnectionResult.NO_SUCH_TX)
                continue;
            // Could not connect this input, so return it and abort.
            return input;
        }
        return null;
    }

    /**
     * @return true if every output is marked as spent.
     */
    public boolean isEveryOutputSpent() {
        for (TransactionOutput output : outputs) {
            if (output.isAvailableForSpending())
                return false;
        }
        return true;
    }
    
    /**
     * @return true if every output owned by a key contained in this
     * 			{@link Wallet} is marked as spent.
     */
    public boolean isEveryOwnedOutputSpent(Wallet wallet) {
    	for (TransactionOutput output : outputs) {
    		if (output.isAvailableForSpending() && output.isMine(wallet)) {
    			return false;
    		}
    	}
    	return true;
    }

    /**
     * Returns the earliest time at which the transaction was seen (broadcast or included into the chain),
     * or null if that information isn't available.
     */
    public Date getUpdateTime() {
        if (updatedAt == null) {
            // Older wallets did not store this field. If we can, fill it out based on the block pointers. We might
            // "guess wrong" in the case of transactions appearing on chain forks, but this is unlikely to matter in
            // practice. Note, some patched copies of BitCoinJ store dates in this field that do not correspond to any
            // block but rather broadcast time.
            if (appearsIn == null || appearsIn.size() == 0) {
                // Transaction came from somewhere that doesn't provide time info.
                return null;
            }
            long earliestTimeSecs = Long.MAX_VALUE;
            // We might return a time that is different to the best chain, as we don't know here which block is part
            // of the active chain and which are simply inactive. We just ignore this for now.
            // TODO: At some point we'll want to store storing full block headers in the wallet. Remove at that time.
            for (StoredBlock b : appearsIn) {
                earliestTimeSecs = Math.min(b.getHeader().getTimeSeconds(), earliestTimeSecs);
            }
            updatedAt = new Date(earliestTimeSecs * 1000);
        }
        return updatedAt;
    }

    /**
     * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
     * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
     * 
     * In the official client, this enum also has another flag, SIGHASH_ANYONECANPAY. In this implementation,
     * that's kept separate. Only SIGHASH_ALL is actually used in the official client today. The other flags
     * exist to allow for distributed contracts.
     */
    public enum SigHash {
        ALL,         // 1
        NONE,        // 2
        SINGLE,      // 3
    }

    void parse() throws ProtocolException {
        version = readUint32();
        // First come the inputs.
        long numInputs = readVarInt();
        inputs = new ArrayList<TransactionInput>((int)numInputs);
        for (long i = 0; i < numInputs; i++) {
            TransactionInput input = new TransactionInput(params, this, bytes, cursor);
            inputs.add(input);
            cursor += input.getMessageSize();
        }
        // Now the outputs
        long numOutputs = readVarInt();
        outputs = new ArrayList<TransactionOutput>((int)numOutputs);
        for (long i = 0; i < numOutputs; i++) {
            TransactionOutput output = new TransactionOutput(params, this, bytes, cursor);
            outputs.add(output);
            cursor += output.getMessageSize();
        }
        lockTime = readUint32();
    }

    /**
     * A coinbase transaction is one that creates a new coin. They are the first transaction in each block and their
     * value is determined by a formula that all implementations of BitCoin share. In 2011 the value of a coinbase
     * transaction is 50 coins, but in future it will be less. A coinbase transaction is defined not only by its
     * position in a block but by the data in the inputs.
     */
    public boolean isCoinBase() {
        return inputs.get(0).isCoinBase();
    }

    /**
     * @return A human readable version of the transaction useful for debugging.
     */
    public String toString() {
        StringBuffer s = new StringBuffer();
        s.append("  ");
        s.append(getHashAsString());
        s.append("\n");
        if (isCoinBase()) {
            String script;
            String script2;
            try {
                script = inputs.get(0).getScriptSig().toString();
                script2 = outputs.get(0).getScriptPubKey().toString();
            } catch (ScriptException e) {
                script = "???";
                script2 = "???";
            }
            return "     == COINBASE TXN (scriptSig " + script + ")  (scriptPubKey " + script2 + ")";
        }
        for (TransactionInput in : inputs) {
            s.append("     ");
            s.append("from ");
            
            try {
                s.append(in.getScriptSig().getFromAddress().toString());
            } catch (Exception e) {
                s.append("[exception: ").append(e.getMessage()).append("]");
                throw new RuntimeException(e);
            }
            s.append("\n");
        }
        for (TransactionOutput out : outputs) {
            s.append("       ");
            s.append("to ");
            try {
                Address toAddr = new Address(params, out.getScriptPubKey().getPubKeyHash());
                s.append(toAddr.toString());
                s.append(" ");
                s.append(bitcoinValueToFriendlyString(out.getValue()));
                s.append(" BTC");
            } catch (Exception e) {
                s.append("[exception: ").append(e.getMessage()).append("]");
            }
            s.append("\n");
        }
        return s.toString();
    }

    /**
     * Adds an input to this transaction that imports value from the given output. Note that this input is NOT
     * complete and after every input is added with addInput() and every output is added with addOutput(),
     * signInputs() must be called to finalize the transaction and finish the inputs off. Otherwise it won't be
     * accepted by the network.
     */
    public void addInput(TransactionOutput from) {
        addInput(new TransactionInput(params, this, from));
    }

    /** Adds an input directly, with no checking that it's valid. */
    public void addInput(TransactionInput input) {
        inputs.add(input);
    }

    /**
     * Adds the given output to this transaction. The output must be completely initialized.
     */
    public void addOutput(TransactionOutput to) {
        to.parentTransaction = this;
        outputs.add(to);
    }

    /**
     * Once a transaction has some inputs and outputs added, the signatures in the inputs can be calculated. The
     * signature is over the transaction itself, to prove the redeemer actually created that transaction,
     * so we have to do this step last.<p>
     *
     * This method is similar to SignatureHash in script.cpp
     *
     * @param hashType This should always be set to SigHash.ALL currently. Other types are unused.
     * @param wallet A wallet is required to fetch the keys needed for signing.
     */
    @SuppressWarnings({"SameParameterValue"})
    public void signInputs(SigHash hashType, Wallet wallet) throws ScriptException {
        assert inputs.size() > 0;
        assert outputs.size() > 0;

        // I don't currently have an easy way to test other modes work, as the official client does not use them.
        assert hashType == SigHash.ALL;

        // The transaction is signed with the input scripts empty except for the input we are signing. In the case
        // where addInput has been used to set up a new transaction, they are already all empty. The input being signed
        // has to have the connected OUTPUT program in it when the hash is calculated!
        //
        // Note that each input may be claiming an output sent to a different key. So we have to look at the outputs
        // to figure out which key to sign with.

        byte[][] signatures = new byte[inputs.size()][];
        ECKey[] signingKeys = new ECKey[inputs.size()];
        for (int i = 0; i < inputs.size(); i++) {
            TransactionInput input = inputs.get(i);
            assert input.scriptBytes.length == 0 : "Attempting to sign a non-fresh transaction";
            // Set the input to the script of its output.
            input.scriptBytes = input.outpoint.getConnectedPubKeyScript();
            // Find the signing key we'll need to use.
            byte[] connectedPubKeyHash = input.outpoint.getConnectedPubKeyHash();
            ECKey key = wallet.findKeyFromPubHash(connectedPubKeyHash);
            // This assert should never fire. If it does, it means the wallet is inconsistent.
            assert key != null : "Transaction exists in wallet that we cannot redeem: " + Utils.bytesToHexString(connectedPubKeyHash);
            // Keep the key around for the script creation step below.
            signingKeys[i] = key;
            // The anyoneCanPay feature isn't used at the moment.
            boolean anyoneCanPay = false;
            byte[] hash = hashTransactionForSignature(hashType, anyoneCanPay);
            // Set the script to empty again for the next input.
            input.scriptBytes = TransactionInput.EMPTY_ARRAY;

            // Now sign for the output so we can redeem it. We use the keypair to sign the hash,
            // and then put the resulting signature in the script along with the public key (below).
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                bos.write(key.sign(hash));
                bos.write((hashType.ordinal() + 1) | (anyoneCanPay ? 0x80 : 0)) ;
                signatures[i] = bos.toByteArray();
            } catch (IOException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
        }

        // Now we have calculated each signature, go through and create the scripts. Reminder: the script consists of
        // a signature (over a hash of the transaction) and the complete public key needed to sign for the connected
        // output.
        for (int i = 0; i < inputs.size(); i++) {
            TransactionInput input = inputs.get(i);
            assert input.scriptBytes.length == 0;
            ECKey key = signingKeys[i];
            input.scriptBytes = Script.createInputScript(signatures[i], key.getPubKey());
        }

        // Every input is now complete.
    }

    private byte[] hashTransactionForSignature(SigHash type, boolean anyoneCanPay) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bitcoinSerializeToStream(bos);
            // We also have to write a hash type.
            int hashType = type.ordinal() + 1;
            if (anyoneCanPay)
                hashType |= 0x80;
            Utils.uint32ToByteStreamLE(hashType, bos);
            // Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
            // however then we would expect that it is IS reversed.
            return doubleDigest(bos.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }
    
    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        uint32ToByteStreamLE(version, stream);
        stream.write(new VarInt(inputs.size()).encode());
        for (TransactionInput in : inputs)
            in.bitcoinSerializeToStream(stream);
        stream.write(new VarInt(outputs.size()).encode());
        for (TransactionOutput out : outputs)
            out.bitcoinSerializeToStream(stream);
        uint32ToByteStreamLE(lockTime, stream);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof Transaction)) return false;
        Transaction t = (Transaction) other;

        return t.getHash().equals(getHash());
    }

    @Override
    public int hashCode() {
        return getHash().hashCode();
    }
}
