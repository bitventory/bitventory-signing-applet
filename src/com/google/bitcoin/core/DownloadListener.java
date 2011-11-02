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

import com.google.bitcoin.core.AbstractPeerEventListener;
import com.google.bitcoin.core.Block;
import com.google.bitcoin.core.Peer;

import java.text.DateFormat;
import java.util.Date;
import java.util.concurrent.Semaphore;

/**
 * Listen to chain download events and print useful informational messages.
 * 
 * <p>progress, startDownload, doneDownload maybe be overridden to change the way the user
 * is notified.  
 * 
 * <p>Methods are called with the event listener object locked so your
 * implementation does not have to be thread safe. 
 * 
 * @author miron@google.com (Miron Cuperman a.k.a. devrandom)
 *
 */
public class DownloadListener extends AbstractPeerEventListener {
    private int originalBlocksLeft = -1;
    private int lastPercent = 0;
    Semaphore done = new Semaphore(0);
    
    @Override
    public void onChainDownloadStarted(Peer peer, int blocksLeft) {
        startDownload(blocksLeft);
        originalBlocksLeft = blocksLeft;
    }
    
    @Override
    public void onBlocksDownloaded(Peer peer, Block block, int blocksLeft) {
        if (blocksLeft == 0) {
            doneDownload();
            done.release();
        }
        
        if (blocksLeft < 0 || originalBlocksLeft <= 0)
            return;

        double pct = 100.0 - (100.0 * (blocksLeft / (double) originalBlocksLeft));
        if ((int)pct != lastPercent) {
            progress(pct, new Date(block.getTimeSeconds() * 1000));
            lastPercent = (int)pct;
        }
    }

    /**
     * Called when download progress is made.
     * 
     * @param pct the percentage of chain downloaded, estimated
     * @param date the date of the last block downloaded 
     */
    protected void progress(double pct, Date date) {
        System.out.println(String.format("Chain download %d%% done, block date %s", (int) pct,
                DateFormat.getDateTimeInstance().format(date)));
    }

    /**
     * Called when download is initiated.
     * 
     * @param blocks the number of blocks to download, estimated
     */
    protected void startDownload(int blocks) {
        System.out.println("Downloading block chain of size " + blocks + ". " +
                (blocks > 1000 ? "This may take a while." : ""));
    }

    /**
     * Called when we are done downloading the block chain.
     */
    protected void doneDownload() {
        System.out.println("Done downloading block chain");
    }

    /**
     * Wait for the chain to be downloaded. 
     */
    public void await() throws InterruptedException {
        done.acquire();
    }
}