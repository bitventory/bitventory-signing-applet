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

package com.bitventory.applet;

// Java core
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

// Library that lets us talk to the browser
import netscape.javascript.JSObject;

// Java Swing library
import javax.swing.JApplet;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

// Bitcoinj library
import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.NetworkParameters;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.core.TransactionOutput;
import com.google.bitcoin.core.Utils;
import com.google.bitcoin.core.Wallet;
import com.google.bitcoin.core.Transaction.SigHash;

// Bitventory code
import com.bitventory.core.Keys;
import com.bitventory.core.Tools;

/**
 * This applet is used for generating public keys on demand from the Bitventory
 * webapp as well as signing transactions which have been built by the service.
 * 
 * @author Ken Burford
 *
 */
@SuppressWarnings("serial")
public class BitAppletThreaded extends JApplet {
	
	/**
	 * If you're compiling your own applet, you can swap in your own
	 * name here to be displayed on the password prompt.
	 */
	private static String owner = "Bitventory.com";
	
	/**
	 * Indicates if the applet is in an unlocked state (passphrase was accepted).
	 */
	private boolean unlocked = false;
	
	/**
	 * The current hashed passphrase used for signing and key generation.
	 * A container is used to allow us to manipulate it from a thread, but not
	 * from the outside. If the web application could set the hash, then
	 * Bitventory or an attacker could override the wallet password. That would
	 * be bad news bears.
	 */
	private HashContainer hashedPassphrase = null;
	
	/**
	 * Handle of the web application's window.
	 */
	private JSObject window = null;
	
	/**
	 * The network type for this session.
	 */
	private NetworkParameters network = null;
	
	/**
	 * Create an empty hash container for the passphrase and
	 * grab the window handle for making JS calls.
	 */
	public void init() {
		
		// Initialize an empty hash container
		this.hashedPassphrase = new HashContainer(null);
		
		// Get the window handle for calling JS methods in the webapp
		this.window = JSObject.getWindow(this);
		
	} // init
	
	/**
	 * Unlock the wallet for the current session.
	 * 
	 * @param email		The user's email address.
	 * @param token		The token of our first key (index 0).
	 * @param pubkey	The public key at index 0.
	 * @param prodnet	Set true for the production chain, false for testnet.
	 * 
	 * @return	True if wallet is unlocked, false if we're starting to unlock.
	 */
	public boolean unlockWallet(String email, byte[] token, byte[] pubkey, boolean prodnet) {
		if (!isUnlocked()) {
			
			// Set the network type
			if (prodnet) network = NetworkParameters.prodNet();
			else network = NetworkParameters.testNet();
			
			// Ask for an unlock
			UnlockThread unlockThread =
				new UnlockThread(this.hashedPassphrase, email, token, pubkey);
			unlockThread.start();
			// Returning false does ~NOT~ mean that it failed.
			// Instead, it means that they should expect a bound
			// callback to fire on success, or the failure method
			// to fire if the unlock is unsuccessful.
			return false;
			
		} else return true;
	} // unlockWallet
	
	/**
	 * Given an address and a token, verify that the address is owned by
	 * and thus under the control of the user.
	 * 
	 * NOTE: This method is fast, so we don't thread it.
	 * 
	 * @param address	The address to verify.
	 * @param token		The token corresponding to the address.
	 */
	public boolean isAddressMine(String address, byte[] token) {
		if (isUnlocked()) {
			VerifyAddressThread addrThread =
				new VerifyAddressThread(this.hashedPassphrase, address, token);
			addrThread.start();
			return true;
		} else return false;
	} // isAddressMine
	
	/**
	 * Let the webapp prompt the user with a transaction to sign.
	 * 
	 * NOTE: Without pulling all input keys from the network, calculating
	 * the fee isn't really feasible. Instead, we hope the user trusts that
	 * we won't give away lots of money to miners. :)
	 * 
	 * NOTE: Signing is fast, so we don't thread this method.
	 * 
	 * @param unsignedTxBytes	A packaged up transaction from the server.
	 * @param keyids			The indices of keys needed for signing.
	 * @param tokens			The tokens corresponding to the input key indices.
	 */
	public boolean signTransaction(byte[] unsignedTxBytes, int[] keyids, byte[][] tokens) {
		if (isUnlocked()) {
			
			// Kick off signing thread
			SignThread signThread =
				new SignThread(this.hashedPassphrase, unsignedTxBytes, keyids, tokens);
			signThread.start();
			
			return true;
		} else return false;
	} // signTransaction
	
	/**
	 * Generate the first key in the user's wallet. This is a special case
	 * because all subsequent keys will be generated after verifying that the
	 * user's passphrase unlocks this first key. So, subsequent key generations
	 * will poll the server for the hash of this public key.
	 * 
	 * NOTE: This method does not require an unlocked wallet! In fact, they
	 * shouldn't have a fucking wallet yet.
	 * 
	 * @param email	The user's email address.
	 * @param token	The initial token, hashed from the shared secret.
	 * 
	 * @return	The public key hash for the user's origin key.
	 */
	public void createOriginKey(String email, byte[] token) {
		
		// Kick off the origin key creation thread
		CreateOriginThread originThread =
			new CreateOriginThread(this.hashedPassphrase, email, token);
		originThread.start();
		
	} // createOriginKey
	
	/**
	 * Generate a new set of public keys on demand from the server. These will
	 * remain stashed in the user's keypool for later use.
	 * 
	 * @param tokens	The tokens of the keys to generate.
	 * 
	 * @return	The generated public keys.
	 */
	public boolean getPublicKeys(byte[][] tokens, int start) {
		if (isUnlocked()) {
			
			// Kick off key generation in thread
			KeygenThread keyThread =
				new KeygenThread(this.hashedPassphrase, tokens, start);
			keyThread.start();
			return true;
			
		} else return false;
	} // getPublicKeys
	
	/**
	 * Check if the wallet is unlocked. By this, we're checking that the user
	 * has entered the correct passphrase and stored the hash in this applet.
	 * 
	 * @return	True is wallet is unlocked, false if not.
	 */
	public boolean isUnlocked() {
		return this.unlocked;
	} // isUnlocked
	
	/**
	 * Allows the user to lock the applet back up, if they're paranoid.
	 */
	public void setLocked() {
		this.unlocked = false;
		this.hashedPassphrase.setHashedPassphrase(null);
	} // setLocked
	
	/**
	 * Call this to mark the user's wallet as unlocked for the duration of the
	 * session.
	 */
	private void setUnlocked() {
		this.unlocked = true;
	} // setUnlocked
	
	/**
	 * Verifies that the passphrase entered by the user combined with the
	 * given token results in the given public key being generated.
	 * 
	 * @param token		The token for key generation.
	 * @param pubkey	The public key to check against.
	 * 
	 * @return	True if the passphrase is valid, and false otherwise.
	 */
	private boolean verifyPassphrase(byte[] token, byte[] pubkey) {
		try {
			ECKey key0 =
				Keys.createKey(this.hashedPassphrase.getHashedPassphrase(), token);
			return Arrays.equals(key0.getPubKey(), pubkey);
		} catch (Exception ex) {} // try
		return false;
	} // verifyPassphrase
	
	/**
	 * A thread used to allow an asynchronous wallet unlock to be performed.
	 */
	private class UnlockThread extends Thread {
		
		/**
		 * Reference to the hashed passphrase for the user.
		 */
		private HashContainer hashedPassphrase = null;
		
		private String email = null;
		private byte[] token = null;
		private byte[] pubkey = null;
		
		/**
		 * Initialize the thread with the hash container.
		 */
		public UnlockThread(HashContainer hashedPassphrase, String email,
				byte[] token, byte[] pubkey) {
			this.hashedPassphrase = hashedPassphrase;
			this.email = email;
			this.token = token;
			this.pubkey = pubkey;
		} // UnlockThread
		
		/**
		 * This fires when the thread starts.
		 */
		public void run() {
			unlockWallet(email, token, pubkey);
		} // run
		
		/**
		 * Performs computationally expensive wallet locking operation in a
		 * thread independent of the core applet.
		 * 
		 * @param email		The user's email address.
		 * @param token		The user's origin token.
		 * @param pubkey	The user's origin key.
		 * @param prodnet	True for production chain, false otherwise.
		 */
		private void unlockWallet(String email, byte[] token, byte[] pubkey) {
			
			// If the user hasn't entered a passphrase, ask for it
			if (!isUnlocked()) {
				String passphrase = promptPassphrase();
				if (passphrase == null) {
					window.call("unlockAppletFailure", null);
				} else {
					
					// Generate the hash of the input passphrase
					// NOTE: No alert needed for threaded version,
					// since we can safely alert in browser with
					// the dialog box and indicator
					//alertHashing();
					this.hashedPassphrase
							.setHashedPassphrase(Keys.generatePassphraseHash(email + passphrase));
					
					// Verify the passphrase
					if (verifyPassphrase(token, pubkey)) {
						setUnlocked();
						window.call("unlockAppletSuccess", null);
					}
					else {
						this.hashedPassphrase.setHashedPassphrase(null);
						window.call("unlockAppletFailure", null);
					}
				}
			}
			
		} // unlockWallet
		
		/**
		 * Prompt the user to enter their passphrase for unlocking their wallet.
		 * 
		 * @return	The passphrase they entered.
		 */
		private String promptPassphrase() {
			
			JPasswordField passField = new JPasswordField();
			passField.setEchoChar('*');
			Object[] body = {"Applet Owner:  " + owner + "\n\n",
					"Please enter your passphrase:\n\n", passField};
			Object[] buttons = {"Unlock","Cancel"};
			
			if (JOptionPane.showOptionDialog(null, body, "Unlock Wallet",
					JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE,
					null, buttons, body) == JOptionPane.YES_OPTION) {
				return new String(passField.getPassword());
			}
			else return null;
			
		} // promptPassphrase
		
	} // UnlockThread
	
	/**
	 * A thread used to allow an asynchronous key generation to be called.
	 */
	private class KeygenThread extends Thread {
		
		private HashContainer hashedPassphrase = null;
		
		private byte[][] tokens = null;
		private int start = -1;
		
		public KeygenThread(HashContainer hashedPassphrase, byte[][] tokens, int start) {
			this.hashedPassphrase = hashedPassphrase;
			this.tokens = tokens;
			this.start = start;
		} // KeygenThread
		
		public void run() {
			getPublicKeys(tokens, start);
		} // run
		
		/**
		 * Generate a new set of public keys on demand from the server. These will
		 * remain stashed in the user's keypool for later use.
		 * 
		 * @param tokens	The tokens of the keys to generate.
		 * @param start		The starting key ID.
		 */
		private void getPublicKeys(byte[][] tokens, int start) {
			
			// Allocate space for keys
			byte[][] keys = new byte[tokens.length][65];
			
			// For all tokens..
			for (int x = 0; x < tokens.length; x++) {
				byte[] token = tokens[x];
				keys[x] =
					Keys.createKey(this.hashedPassphrase.getHashedPassphrase(),
							token).getPubKey();
			} // for
			
			// Fire key upload callback
			Object[] args = {keys, start};
			window.call("submitKeys", args);
			
		} // getPublicKeys
		
	} // KeygenThread
	
	/**
	 * A thread used to allow an asynchronous address check.
	 */
	private class VerifyAddressThread extends Thread {
		
		private HashContainer hashedPassphrase = null;
		
		private String address = null;
		private byte[] token = null;
		
		public VerifyAddressThread(HashContainer hashedPassphrase, String address,
				byte[] token) {
			this.hashedPassphrase = hashedPassphrase;
			this.address = address;
			this.token = token;
		} // KeygenThread
		
		public void run() {
			isAddressMine(address, token);
		} // run
		
		/**
		 * Given an address and a token, verify that the address is owned by
		 * and thus under the control of the user.
		 * 
		 * NOTE: This method is fast, so we don't thread it.
		 * 
		 * @param address	The address to verify.
		 * @param token		The token corresponding to the address.
		 * 
		 * @return	True if address is verified, false if not.
		 */
		public boolean isAddressMine(String address, byte[] token) {
			
			try {
			
				// Get an address instance from the address string,
				// and use it to derive the the hash160
				Address addr = new Address(network, address);
				byte[] hash160 = addr.getHash160();
				
				// Generate the user's key for this address
				ECKey key =
					Keys.createKey(this.hashedPassphrase.getHashedPassphrase(), token);
				
				// Is this key owned by the user?
				if (Arrays.equals(hash160, key.getPubKeyHash())) {
					notify("You are the rightful owner of the address: " + address, true);
					return true;
				}
				
			} catch (Exception ex) {
				ex.printStackTrace();
			} // try
			
			notify("This key is either invalid, or not owned by this wallet.", false);
			return false;
			
		} // isAddressMine
		
		/**
		 * Pop up an alert dialog with some sort of important message.
		 * 
		 * @param message	The message to send the user.
		 * @param warn		True for a warning dialog, or false for an error.
		 */
		private void notify(String message, boolean warn) {
			int type = JOptionPane.ERROR_MESSAGE;
			if (warn) type = JOptionPane.WARNING_MESSAGE;
			JOptionPane pane = new JOptionPane();
			JOptionPane.showMessageDialog(pane, message,
					"Bitventory Signing Applet", type);
		} // notify
		
	} // VerifyAddressThread

	/**
	 * A thread used to allow an asynchronous tx signing.
	 */
	private class SignThread extends Thread {
		
		private HashContainer hashedPassphrase = null;
		
		private byte[] unsignedTxBytes = null;
		private int[] keyids = null;
		private byte[][] tokens = null;
		
		public SignThread(HashContainer hashedPassphrase, byte[] unsignedTxBytes,
				int[] keyids, byte[][] tokens) {
			this.hashedPassphrase = hashedPassphrase;
			this.unsignedTxBytes = unsignedTxBytes;
			this.keyids = keyids;
			this.tokens = tokens;
		} // KeygenThread
		
		public void run() {
			signTransaction(unsignedTxBytes, keyids, tokens);
		} // run
		
		/**
		 * Let the webapp prompt the user with a transaction to sign.
		 * 
		 * NOTE: Without pulling all input keys from the network, calculating
		 * the fee isn't really feasible. Instead, we hope the user trusts that
		 * we won't give away lots of money to miners. :)
		 * 
		 * NOTE: Signing is fast, so we don't thread this method.
		 * 
		 * @param unsignedTxBytes	A packaged up transaction from the server.
		 * @param keyids			The indices of keys needed for signing.
		 * @param tokens			The tokens corresponding to the input key indices.
		 */
		private void signTransaction(byte[] unsignedTxBytes, int[] keyids, byte[][] tokens) {
			
			try {
				
				// Convert the compressed transaction built by the service back into
				// a Transaction object
				Transaction tx = (Transaction)Tools.deserializeFromBytes(unsignedTxBytes);
				
				// Create a temporary wallet
				Wallet wallet = new Wallet(network);
				
				// Generate the needed keys for the wallet
				for (int x = 0; x < keyids.length; x++) {
					byte[] token = tokens[x];
					wallet.addKey(Keys.createKey(this.hashedPassphrase.getHashedPassphrase(), token));
				} // for
				
				// Verify that I'm not an evil jackass
				List<TransactionOutput> outputs = tx.getOutputs();
				if ((outputs.size() >= 2) && (outputs.size() <= 3)) {
					
					// Get the sum of the outputs
					BigInteger outputTotal = BigInteger.ZERO;
					for (TransactionOutput output : outputs) {
						outputTotal = outputTotal.add(output.getValue());
					} // for
					
					// Get receiver details
					TransactionOutput receiver = outputs.get(0);
					String receiverCoins =
						Utils.bitcoinValueToFriendlyString(receiver.getValue());
					String receiverAddress =
						receiver.getScriptPubKey().getToAddress().toString();
					
					// Get service fee details
					TransactionOutput yaymonies = outputs.get(1);
					String serviceFee =
						Utils.bitcoinValueToFriendlyString(yaymonies.getValue());
					
					// If there is change, verify that the user controls the
					// output address
					if (outputs.size() == 3) {
						TransactionOutput change = outputs.get(2);
						if (!change.isMine(wallet)) {
							String message =
								"WARNING! The change address for this transaction " +
								"is not yours! Signing aborted.";
							notify(message, false);
							return;
						}
					}
					
					String networkFee =
						Utils.bitcoinValueToFriendlyString(tx.getFeeValue());
					
					// Ask the user if they want to sign with the above information
					if (askForAuthorization(receiverAddress, receiverCoins,
							networkFee, serviceFee)) {
						
						// Sign the transaction with the current wallet
						tx.signInputs(SigHash.ALL, wallet);
						
						// Compress the signed transaction and send it back
						Object[] args = {Tools.serializeToBytes(tx)};
						window.call("sendSignedTx", args);
						return;
						
					} else notify("You declined to sign the transaction.", true);
					
				} else return;
			
			} catch (Exception ex) {
				ex.printStackTrace();
				System.err.println(ex.getMessage());
				notify(ex.getMessage(), false);
				return;
			} // try
			
			// Something went wrong
			return;
			
		} // signTransaction
		
		/**
		 * Display a dialog box asking the user to sign off on a transaction
		 * that has been built by the server.
		 * 
		 * This dialog serves to verify that the {@link Transaction} built by the
		 * service is as the user requested. If the receive address doesn't match,
		 * or the amount is incorrect, then the user can abort the transaction
		 * safely. 
		 * 
		 * @param address		The confirmed receive address.	
		 * @param amount		The confirmed amount to send.
		 * @param networkFee	The network fee we're paying the solving node.
		 * @param serviceFee	The service fee Bitventory is charging for the send.
		 * 
		 * @return	True if the user authorized the send, and false otherwise.
		 */
		private boolean askForAuthorization(String address, String amount,
				String networkFee, String serviceFee) {
			
			String message =
				"You have requested a transaction.\n\n" +
				"  To: " + address + "\n" +
				"  Amount: " + amount + " BTC\n" +
				"  Network Fee: " + networkFee + " BTC\n" +
				"  Bitventory Fee: " + serviceFee + " BTC\n\n" +
				"Please verify that these details are correct.\n" +
				"This information is extracted from the transaction\n" +
				"the service is asking you to sign. If Bitventory.com\n" +
				"has become evil, or someone has compromised your\n" +
				"connection to the Internet, then these details\n" +
				"will be altered.\n\n" +
				"Note: The network fee is reported by the server,\n" +
				"not by checking the transaction itself. This value\n" +
				"goes to lucky Bitcoin miners as a reward for protecting\n" +
				"the Bitcoin network, not to Bitventory.com\n\n" +
				"Would you like to sign and authorize this transaction?";
			JOptionPane pane = new JOptionPane(message);
			Object[] opts = new String[] { "Authorize", "Cancel" };
			pane.setOptions(opts);
			JDialog dialog =
				pane.createDialog(new JFrame(), "Payment Confirmation");
			dialog.setVisible(true);
			String result = (String)pane.getValue();
			if (result.equals("Authorize")) return true;
			else return false;
			
		} // askForAuthorization
		
		/**
		 * Pop up an alert dialog with some sort of important message.
		 * 
		 * @param message	The message to send the user.
		 * @param warn		True for a warning dialog, or false for an error.
		 */
		private void notify(String message, boolean warn) {
			int type = JOptionPane.ERROR_MESSAGE;
			if (warn) type = JOptionPane.WARNING_MESSAGE;
			JOptionPane pane = new JOptionPane();
			JOptionPane.showMessageDialog(pane, message,
					"Bitventory Signing Applet", type);
		} // notify
		
	} // SignThread
	
	/**
	 * A thread used to allow an asynchronous origin key generation.
	 */
	private class CreateOriginThread extends Thread {
		
		private HashContainer hashedPassphrase = null;
		
		private String email = null;
		private byte[] token = null;
		
		public CreateOriginThread(HashContainer hashedPassphrase, String email,
				byte[] token) {
			this.hashedPassphrase = hashedPassphrase;
			this.email = email;
			this.token = token;
		} // KeygenThread
		
		public void run() {
			createOriginKey(email, token);
		} // run
		
		/**
		 * Generate the first key in the user's wallet. This is a special case
		 * because all subsequent keys will be generated after verifying that the
		 * user's passphrase unlocks this first key. So, subsequent key generations
		 * will poll the server for the hash of this public key.
		 * 
		 * NOTE: This method does not require an unlocked wallet! In fact, they
		 * shouldn't have a fucking wallet yet.
		 * 
		 * @param email	The user's email address.
		 * @param token	The initial token, hashed from the shared secret.
		 */
		private void createOriginKey(String email, byte[] token) {
			
			// Verify that we have a proper email
			if ((email == null) || (email.equals(""))) {
				notify("Invalid email address.", false);
				return;
			}
			
			// Verify that we have a proper token
			if ((token == null) || (token.length != 64)) {
				notify("Invalid initialization token.", false);
				return;
			}
			
			// Prompt the user to set a passphrase
			String passphrase = firstPassphrase();
			if (passphrase == null) {
				notify("Your passwords did not match.", false);
				return;
			}
			
			// Hash the passphrase (not threaded currently)
			alertHashing();
			this.hashedPassphrase.setHashedPassphrase(Keys.generatePassphraseHash(email + passphrase));
			
			// Generate the origin key
			ECKey originKey =
				Keys.createKey(this.hashedPassphrase.getHashedPassphrase(), token);
			
			// Submit the origin key
			Object[] args = {originKey.getPubKey()};
			window.call("askForOriginNext", args);
			
		} // createOriginKey
		
		/**
		 * Prompt the user to set their passphrase. This passphrase dialog is
		 * only used at account creation!
		 * 
		 * @return	The origin passphrase.
		 */
		private String firstPassphrase() {
			
			JTextField textField = new JTextField();
			Object[] body =
				{"You are about to initialize your online wallet.\n\n" +
					"Some words of warning:\n\n" +
					"  1. If you forget this passphrase, your money is\n" +
					"     gone forever. We cannot retrieve it (and for\n" +
					"     good reason). Write it somewhere safe!\n\n" +
					"  2. This password input box is not concealed. You\n" +
					"     will be able to read it and verify it before\n" +
					"     submitting. Please be sure no one is looking!\n" +
					"     When asked for your passphrase later, it will\n" +
					"     be hidden from view.\n\n" +
					"  3. Your passphrase should be strong, but it need not\n" +
					"     necessarily be so complex as to be unmemorable.\n" +
					"     This passphrase is only half of the the key protecting\n" +
					"     your wallet, and is mostly intended to protect you\n" +
					"     from man-in-the-middle attacks, and most importantly:\n" +
					"     it protects you from us here at Bitventory.com if we\n" +
					"     become evil or greedy.\n\n" +
					"With the above in mind, please enter your new passphrase:\n\n", textField};
			Object[] buttons = {"Confirm","Cancel"};
			
			String passphrase = null;
			if (JOptionPane.showOptionDialog(null, body, "Initialize Wallet",
					JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE,
					null, buttons, body) == JOptionPane.YES_OPTION) {
				passphrase = new String(textField.getText());
			}
			else return null;
			
			if ((passphrase == null) || (passphrase.equals(""))) return null;
			
			textField = new JTextField();
			Object[] body1 = {"Please confirm your passphrase: ", textField};
			Object[] buttons1 = {"I'm sure!","Cancel"};
			
			if (JOptionPane.showOptionDialog(null, body1, "Confirm Passphrase",
					JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE,
					null, buttons1, body1) == JOptionPane.YES_OPTION) {
				String confirm = new String(textField.getText());
				if (passphrase.equals(confirm)) return passphrase;
				else return null;
			}
			else return null;
			
		} // firstPassphrase
		
		private void alertHashing() {
			notify("Your wallet is about to be unlocked. This action\n" +
					"results in a large number of hash operations being\n" +
					"performed to increase the strength of your wallet\n" +
					"against outside attacks. This will take between\n" +
					"5-45 seconds, depending on your hardware. Your\n" +
					"browser may become non-responsive while this is run.\n\n" +
					"Thanks for your patience. :)", true);
		} // alertHashing
		
		/**
		 * Pop up an alert dialog with some sort of important message.
		 * 
		 * @param message	The message to send the user.
		 * @param warn		True for a warning dialog, or false for an error.
		 */
		private void notify(String message, boolean warn) {
			int type = JOptionPane.ERROR_MESSAGE;
			if (warn) type = JOptionPane.WARNING_MESSAGE;
			JOptionPane pane = new JOptionPane();
			JOptionPane.showMessageDialog(pane, message,
					"Bitventory Signing Applet", type);
		} // notify
		
	} // CreateOriginThread
	
	/**
	 * A container for storing the user's wallet passphrase hash. We need
	 * something we can manipulate the hash of while passing by reference,
	 * without making the hash public (so the thread an access it).
	 */
	public class HashContainer {
		
		private byte[] hashedPassphrase = null;
		
		public HashContainer(byte[] hashedPassphrase) {
			this.hashedPassphrase = hashedPassphrase;
		} // HashContainer
		
		public void setHashedPassphrase(byte[] hashedPassphrase) {
			this.hashedPassphrase = hashedPassphrase;
		} // setHashedPassphrase
		
		public byte[] getHashedPassphrase() {
			return this.hashedPassphrase;
		} // getHashedPassphrase
		
	} // HashContainer
	
} // BitAppletThreaded
