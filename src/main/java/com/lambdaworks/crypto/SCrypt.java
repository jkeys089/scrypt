// Copyright (C) 2011 - Will Glozer.  All rights reserved.

package com.lambdaworks.crypto;

/**
 * An implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt</a>
 * key derivation function. This class will attempt to load a native library
 * containing the optimized C implementation from
 * <a href="http://www.tarsnap.com/scrypt.html">http://www.tarsnap.com/scrypt.html<a>
 *
 * @author  Will Glozer
 */
public class SCrypt {

    /**
     * Flag used to determine if native scrypt library was successfully loaded or not.
     */
    public static final boolean NATIVE_LIBRARY_LOADED;

    private static final RuntimeException not_loaded_exception;

    static {

        String notLoadedMsg = "scrypt library is not loaded";
        Throwable notLoadedCause = null;
        boolean loaded = false;

        try {
            System.loadLibrary("scrypt");
            loaded = true;
        } catch (Throwable e) {
            notLoadedMsg = notLoadedMsg + ": " + e.getMessage();
            notLoadedCause = e;
            e.printStackTrace();
        } finally {
            NATIVE_LIBRARY_LOADED = loaded;
            if (notLoadedCause == null) {
                not_loaded_exception = new RuntimeException(notLoadedMsg);
            } else {
                not_loaded_exception = new RuntimeException(notLoadedMsg, notLoadedCause);
            }
        }

    }

    /**
     * Convenience method for safely calling the native scrypt implementation.
     *
     * First checks <code>NATIVE_LIBRARY_LOADED</code> flag and throws a cached <code>RuntimeException</code> if the native scrypt library is not loaded.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     */
    public static byte[] scrypt(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen) {
        if (!NATIVE_LIBRARY_LOADED) {
            throw not_loaded_exception;
        } else {
            return scryptN(passwd, salt, N, r, p, dkLen);
        }
    };

    /**
     * Native C implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a> using
     * the code from <a href="http://www.tarsnap.com/scrypt.html">http://www.tarsnap.com/scrypt.html<a>.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     */
    public static native byte[] scryptN(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen);

}
