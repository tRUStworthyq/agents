package com.trustworthyq.agents.s3.service;

import com.trustworthyq.agents.pii.service.PiiDetector;

import io.micrometer.core.instrument.Timer;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

record ContentHashes(String sha256, String simhash) {
    static ContentHashes read(InputStream input, long expectedBytes, PiiDetector detector, Timer timer) throws IOException {
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }

        long[] weights = new long[Long.SIZE];
        long size = 0;
        int window = 0;
        byte[] buffer = new byte[64 * 1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
            sha256.update(buffer, 0, count);
            if (detector != null) {
                int length = count;
                timer.record(() -> detector.feed(buffer, length));
            }
            for (int index = 0; index < count; index++) {
                window = (window << 8) | Byte.toUnsignedInt(buffer[index]);
                if (++size >= Integer.BYTES) {
                    vote(weights, window);
                }
            }
        }
        if (size != expectedBytes) {
            throw new IOException("S3 object length changed during read");
        }
        if (size > 0 && size < Integer.BYTES) {
            vote(weights, (size << Integer.SIZE) | Integer.toUnsignedLong(window));
        }
        long fingerprint = 0;
        for (int bit = 0; bit < weights.length; bit++) {
            if (weights[bit] > 0) {
                fingerprint |= 1L << bit;
            }
        }
        return new ContentHashes(HexFormat.of().formatHex(sha256.digest()),
                HexFormat.of().toHexDigits(fingerprint));
    }

    private static void vote(long[] weights, long feature) {
        // Mix each overlapping four-byte feature before adding its SimHash vote.
        long hash = (feature ^ (feature >>> 30)) * 0xbf58476d1ce4e5b9L;
        hash = (hash ^ (hash >>> 27)) * 0x94d049bb133111ebL;
        hash ^= hash >>> 31;
        for (int bit = 0; bit < weights.length; bit++) {
            weights[bit] += ((hash >>> bit) & 1L) == 0 ? -1 : 1;
        }
    }
}
