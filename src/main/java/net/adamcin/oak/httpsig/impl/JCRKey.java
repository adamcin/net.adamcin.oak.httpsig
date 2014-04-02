/*
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org/>
 */

package net.adamcin.oak.httpsig.impl;

import net.adamcin.httpsig.api.Algorithm;
import net.adamcin.httpsig.api.UserKey;
import net.adamcin.httpsig.ssh.jce.FingerprintableKey;

import java.util.Set;

/**
 * Wrapper for JCEKeys which implements {@link UserKey} and {@link net.adamcin.httpsig.ssh.jce.FingerprintableKey}
 */
public class JCRKey implements UserKey, FingerprintableKey {

    private final String userId;
    private final FingerprintableKey key;

    public JCRKey(String userId, FingerprintableKey key) {
        this.userId = userId;
        this.key = key;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getFingerprint() {
        return key.getFingerprint();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getUserId() {
        return userId;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getId() {
        return key.getId();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<Algorithm> getAlgorithms() {
        return key.getAlgorithms();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canVerify() {
        return key.canVerify();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(Algorithm algorithm, byte[] contentBytes, byte[] signatureBytes) {
        return key.verify(algorithm, contentBytes, signatureBytes);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canSign() {
        return key.canSign();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] sign(Algorithm algorithm, byte[] contentBytes) {
        return key.sign(algorithm, contentBytes);
    }
}
