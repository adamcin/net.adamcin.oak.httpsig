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

import net.adamcin.httpsig.api.DefaultVerifier;
import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.api.VerifyResult;
import net.adamcin.oak.httpsig.HttpsigCredentials;
import net.adamcin.httpsig.api.UserKey;
import org.apache.jackrabbit.oak.spi.security.authentication.Authentication;

import javax.jcr.Credentials;
import javax.security.auth.login.LoginException;

/**
 * Created by madamcin on 3/23/14.
 */
public class HttpsigAuthentication implements Authentication {

    private Verifier verifier;
    private VerifyResult result;
    private String userId;

    public HttpsigAuthentication(Verifier verifier) {
        this.verifier = verifier;
    }

    public boolean authenticate(Credentials credentials) throws LoginException {
        if (verifier != null && credentials instanceof HttpsigCredentials) {
            HttpsigCredentials creds = (HttpsigCredentials) credentials;
            Key key = verifier.selectKey(creds.getAuthorization());
            if (key instanceof UserKey && verifyCredentials(creds)) {
                userId = ((UserKey) key).getUserId();
                return true;
            }
        }
        return false;
    }

    public String getUserId() {
        return userId;
    }

    private boolean verifyCredentials(HttpsigCredentials credentials) throws LoginException {
        return verifier.verify(credentials.getChallenge(),
                credentials.getRequestContent(),
                credentials.getAuthorization());
    }
}
