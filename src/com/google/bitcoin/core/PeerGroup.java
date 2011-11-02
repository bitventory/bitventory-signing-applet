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

import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Maintain a number of connections to peers.
 * 
 * <p>PeerGroup tries to maintain a constant number of connections to a set of distinct peers.
 * Each peer runs a network listener in its own thread.  When a connection is lost, a new peer
 * will be tried after a delay as long as the number of connections less than the maximum.
 * 
 * <p>Connections are made to addresses from a provided list.  When that list is exhausted,
 * we start again from the head of the list.
 * 
 * <p>The PeerGroup can broadcast a transaction to the currently connected set of peers.  It can
 * also handle download of the blockchain from peers, restarting the process when peers die.
 * 
 * @author miron@google.com (Miron Cuperman a.k.a devrandom)
 *
 */
public class PeerGroup {
    private static final int DEFAULT_CONNECTIONS = 4;

    private static final Logger log = LoggerFactory.getLogger(PeerGroup.class);
    
    public static final int DEFAULT_CONNECTION_DELAY_MILLIS = 5 * 1000;
    private static final int CORE_THREADS = 1;
    private static final int THREAD_KEEP_ALIVE_SECONDS = 1;

    // Addresses to try to connect to, excluding active peers
    private BlockingQueue<PeerAddress> inactives;
    // Connection initiation thread
    private Thread connectThread;
    // True if the connection initiation thread should be running
    private boolean running;
    // A pool of threads for peers, of size maxConnection
    private ThreadPoolExecutor peerPool;
    // Currently active peers
    private Set<Peer> peers;
    // The peer we are currently downloading the chain from
    private Peer downloadPeer;
    // Callback for events related to chain download
    private PeerEventListener downloadListener;
    // Callbacks for events related to peer connection/disconnection
    private Set<PeerEventListener> peerEventListeners;
    // Peer discovery sources, will be polled occasionally if there aren't enough inactives.
    private Set<PeerDiscovery> peerDiscoverers;
    
    private NetworkParameters params;
    private BlockStore blockStore;
    private BlockChain chain;
    private int connectionDelayMillis;

    /**
     * Creates a PeerGroup with the given parameters and a default 5 second connection timeout.
     */
    public PeerGroup(BlockStore blockStore, NetworkParameters params, BlockChain chain) {
        this(blockStore, params, chain, DEFAULT_CONNECTION_DELAY_MILLIS);
    }

    /**
     * Creates a PeerGroup with the given parameters. The connectionDelayMillis parameter controls how long the
     * PeerGroup will wait between attempts to connect to nodes or read from any added peer discovery sources.
     */
    public PeerGroup(BlockStore blockStore, NetworkParameters params, BlockChain chain, int connectionDelayMillis) {
        this.blockStore = blockStore;
        this.params = params;
        this.chain = chain;
        this.connectionDelayMillis = connectionDelayMillis;

        inactives = new LinkedBlockingQueue<PeerAddress>();
        peers = Collections.synchronizedSet(new HashSet<Peer>());
        peerEventListeners = Collections.synchronizedSet(new HashSet<PeerEventListener>());
        peerDiscoverers = Collections.synchronizedSet(new HashSet<PeerDiscovery>());
        peerPool = new ThreadPoolExecutor(CORE_THREADS, DEFAULT_CONNECTIONS,
                THREAD_KEEP_ALIVE_SECONDS, TimeUnit.SECONDS,
                new LinkedBlockingQueue<Runnable>(1),
                new PeerGroupThreadFactory());
    }

    /**
     * Callbacks to the listener are performed in the connection thread.  The callback
     * should not perform time consuming tasks.
     */
    public void addEventListener(PeerEventListener listener) {
        peerEventListeners.add(listener);
    }
    
    public boolean removeEventListener(PeerEventListener listener) {
        return peerEventListeners.remove(listener);
    }
    
    /**
     * Depending on the environment, this should normally be between 1 and 10, default is 4.
     * 
     * @param maxConnections the maximum number of peer connections that this group will try to make.
     */
    public void setMaxConnections(int maxConnections) {
        peerPool.setMaximumPoolSize(maxConnections);
    }
    
    public int getMaxConnections() {
        return peerPool.getMaximumPoolSize();
    }
    
    /** Add an address to the list of potential peers to connect to */
    public void addAddress(PeerAddress peerAddress) {
        // TODO(miron) consider deduplication
        inactives.add(peerAddress);
    }
    
    /** Add addresses from a discovery source to the list of potential peers to connect to */
    public void addPeerDiscovery(PeerDiscovery peerDiscovery) {
        peerDiscoverers.add(peerDiscovery);
    }
    
    /** Starts the background thread that makes connections. */
    public void start() {
        this.connectThread = new Thread(new PeerExecutionRunnable(), "Peer group thread");
        running = true;
        this.connectThread.start();
    }

    /**
     * Stop this PeerGroup
     * 
     * <p>The peer group will be asynchronously shut down.  After it is shut down
     * all peers will be disconnected and no threads will be running.
     */
    public synchronized void stop() {
        if (running) {
            connectThread.interrupt();
        }
    }

    /**
     * Broadcast a transaction to all connected peers
     * 
     * @return whether we sent to at least one peer
     */
    public boolean broadcastTransaction(Transaction tx) {
        boolean success = false;
        synchronized (peers) {
            for (Peer peer : peers) {
                try {
                    peer.broadcastTransaction(tx);
                    success = true;
                } catch (IOException e) {
                    log.error("failed to broadcast to " + peer, e);
                }
            }
        }
        return success;
    }

    private final class PeerExecutionRunnable implements Runnable {
        /**
         * Repeatedly get the next peer address from the inactive queue
         * and try to connect.
         * 
         * <p>We can be terminated with Thread.interrupt.  When an interrupt is received,
         * we will ask the executor to shutdown and ask each peer to disconnect.  At that point
         * no threads or network connections will be active.
         */
        public void run() {
            try {
                while (running) {
                    if (inactives.size() == 0) {
                        discoverPeers();
                    } else {
                        tryNextPeer();
                    }
                    
                    // We started a new peer connection, delay before trying another one
                    Thread.sleep(connectionDelayMillis);
                }
            } catch (InterruptedException ex) {
                synchronized (this) {
                    running = false;
                }
            }
            peerPool.shutdownNow();
            synchronized (peers) {
                for (Peer peer : peers) {
                    peer.disconnect();
                }
            }
        }

        private void discoverPeers() {
            for (PeerDiscovery peerDiscovery : peerDiscoverers) {
                InetSocketAddress[] addresses;
                try {
                    addresses = peerDiscovery.getPeers();
                } catch (PeerDiscoveryException e) {
                    // Will try again later.
                    log.error("Failed to discover peer addresses from discovery source", e);
                    return;
                }

                for (int i = 0; i < addresses.length; i++) {
                    inactives.add(new PeerAddress(addresses[i]));
                }

                if (inactives.size() > 0) break;
            }
        }

        /** Try connecting to a peer.  If we exceed the number of connections, delay and try again. */
        private void tryNextPeer() throws InterruptedException {
            final PeerAddress address = inactives.take();
            while (true) {
                try {
                    final Peer peer = new Peer(params, address, blockStore.getChainHead().getHeight(), chain);
                    Runnable command = new Runnable() {
                        public void run() {
                            try {
                                log.info("Connecting to " + peer);
                                peer.connect();
                                peers.add(peer);
                                handleNewPeer(peer);
                                peer.run();
                            } catch (PeerException ex) {
                                // Do not propagate PeerException - log and try next peer. Suppress stack traces for
                                // exceptions we expect as part of normal network behaviour.
                                final Throwable cause = ex.getCause();
                                if (cause instanceof SocketTimeoutException) {
                                    log.info("Timeout talking to " + peer + ": " + cause.getMessage());
                                } else if (cause instanceof ConnectException) {
                                    log.info("Could not connect to " + peer + ": " + cause.getMessage());
                                } else if (cause instanceof IOException) {
                                    log.info("Error talking to " + peer + ": " + cause.getMessage());
                                } else {
                                    log.error("Unexpected exception whilst talking to " + peer, ex);
                                }
                            } finally {
                                // In all cases, disconnect and put the address back on the queue.
                                // We will retry this peer after all other peers have been tried.
                                peer.disconnect();

                                inactives.add(address);
                                if (peers.remove(peer))
                                    handlePeerDeath(peer);
                            }
                        }
                    };
                    peerPool.execute(command);
                    break;
                } catch (RejectedExecutionException e) {
                    // Reached maxConnections, try again after a delay

                    // TODO - consider being smarter about retry.  No need to retry
                    // if we reached maxConnections or if peer queue is empty.  Also consider
                    // exponential backoff on peers and adjusting the sleep time according to the
                    // lowest backoff value in queue.
                } catch (BlockStoreException e) {
                    // Fatal error
                    log.error("Block store corrupt?", e);
                    running = false;
                    throw new RuntimeException(e);
                }
                
                // If we got here, we should retry this address because an error unrelated
                // to the peer has occurred.
                Thread.sleep(connectionDelayMillis);
            }
        }
    }

    /**
     * Start downloading the blockchain from the first available peer.
     * 
     * <p>If no peers are currently connected, the download will be started
     * once a peer starts.  If the peer dies, the download will resume with another peer.
     * 
     * @param listener a listener for chain download events, may not be null
     */
    public synchronized void startBlockChainDownload(PeerEventListener listener) {
        this.downloadListener = listener;
        // TODO be more nuanced about which peer to download from.  We can also try
        // downloading from multiple peers and handle the case when a new peer comes along
        // with a longer chain after we thought we were done.
        synchronized (peers) {
            if (!peers.isEmpty())
            {
                startBlockChainDownloadFromPeer(peers.iterator().next());
            }
        }
    }
    
    /**
     * Download the blockchain from peers.<p>
     * 
     * This method waits until the download is complete.  "Complete" is defined as downloading
     * from at least one peer all the blocks that are in that peer's inventory.
     */
    public void downloadBlockChain() {
        DownloadListener listener = new DownloadListener();
        startBlockChainDownload(listener);
        try {
            listener.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
    
    protected synchronized void handleNewPeer(Peer peer) {
        if (downloadListener != null && downloadPeer == null)
            startBlockChainDownloadFromPeer(peer);
        synchronized (peerEventListeners) {
            for (PeerEventListener listener : peerEventListeners) {
                synchronized (listener) {
                    listener.onPeerConnected(peer, peers.size());
                }
            }
        }
    }
    
    protected synchronized void handlePeerDeath(Peer peer) {
        if (peer == downloadPeer) {
            downloadPeer = null;
            synchronized (peers) {
                if (downloadListener != null && !peers.isEmpty()) {
                    startBlockChainDownloadFromPeer(peers.iterator().next());
                }
            }
        }

        synchronized (peerEventListeners) {
            for (PeerEventListener listener : peerEventListeners) {
                synchronized (listener) {
                    listener.onPeerDisconnected(peer, peers.size());
                }
            }
        }
    }

    private synchronized void startBlockChainDownloadFromPeer(Peer peer) {
        peer.addEventListener(downloadListener);
        try {
            peer.startBlockChainDownload();
        } catch (IOException e) {
            log.error("failed to start block chain download from " + peer, e);
            return;
        }
        downloadPeer = peer;
    }
    
    static class PeerGroupThreadFactory implements ThreadFactory {
        static final AtomicInteger poolNumber = new AtomicInteger(1);
        final ThreadGroup group;
        final AtomicInteger threadNumber = new AtomicInteger(1);
        final String namePrefix;

        PeerGroupThreadFactory() {
            group = Thread.currentThread().getThreadGroup();
            namePrefix = "PeerGroup-" +
                          poolNumber.getAndIncrement() +
                         "-thread-";
        }

        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r,
                                  namePrefix + threadNumber.getAndIncrement(),
                                  0);
            // Lower the priority of the peer threads. This is to avoid competing with UI threads created by the API
            // user when doing lots of work, like downloading the block chain. We select a priority level one lower
            // than the parent thread, or the minimum.
            t.setPriority(Math.max(Thread.MIN_PRIORITY, Thread.currentThread().getPriority() - 1));
            t.setDaemon(true);
            return t;
        }
    }
}
