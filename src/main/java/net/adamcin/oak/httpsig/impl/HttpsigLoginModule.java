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
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.oak.httpsig.HttpsigConfiguration;
import net.adamcin.oak.httpsig.HttpsigCredentials;
import net.adamcin.oak.httpsig.VerifierCallback;
import org.apache.jackrabbit.oak.api.AuthInfo;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.apache.jackrabbit.oak.spi.security.authentication.AbstractLoginModule;
import org.apache.jackrabbit.oak.spi.security.authentication.AuthInfoImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.jcr.Credentials;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.Set;

/**
 * Created by madamcin on 3/23/14.
 */
public final class HttpsigLoginModule extends AbstractLoginModule {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpsigLoginModule.class);

    protected static final Set<Class> SUPPORTED_CREDENTIALS =
            Collections.<Class>singleton(HttpsigCredentials.class);

    private HttpsigCredentials httpsigCredentials;
    private Verifier verifier;
    private String userId;
    private Set<? extends Principal> principals;

    //--------------------------------------------------------< LoginModule >---

    /**
     * TODO handle impersonation
     * {@inheritDoc}
     */
    @Override
    public boolean login() throws LoginException {
        verifier = getVerifier();
        if (verifier == null) {
            return false;
        }

        Credentials credentials = getCredentials();

        if (credentials instanceof HttpsigCredentials) {
            HttpsigCredentials creds = (HttpsigCredentials) credentials;
            HttpsigAuthentication authentication = new HttpsigAuthentication(getVerifier());

            if (authentication.authenticate(creds)) {
                this.httpsigCredentials = creds;
                this.userId = authentication.getUserId();
                this.principals = this.getPrincipals(this.userId);
                return true;
            } else {
            }
        }

        return false;
    }

    /**
     * TODO handle {@link #SHARED_KEY_CREDENTIALS}
     * {@inheritDoc}
     */
    @Override
    public boolean commit() throws LoginException {
        if (httpsigCredentials != null) {
            updateSubject(httpsigCredentials, getAuthInfo(), principals);
            return true;
        }

        clearState();
        return false;
    }

    //------------------------------------------------< AbstractLoginModule >---
    @Nonnull
    @Override
    protected Set<Class> getSupportedCredentials() {
        return SUPPORTED_CREDENTIALS;
    }

    @Override
    protected void clearState() {
        super.clearState();

        this.httpsigCredentials = null;
        this.userId = null;
        this.principals = null;
    }

    //------------------------------------------------------------< private >---

    /**
     * Create the {@code AuthInfo} for the specified {@code tokenInfo} as well as
     * userId and principals, that have been set upon {@link #login}.
     *
     * @return The {@code AuthInfo} resulting from the successful login.
     */
    @CheckForNull
    private AuthInfo getAuthInfo() {
        if (userId != null) {
            return new AuthInfoImpl(this.userId, Collections.<String, Object>emptyMap(), principals);
        } else {
            return null;
        }
    }

    private void updateSubject(@Nonnull HttpsigCredentials tc, @Nullable AuthInfo authInfo,
                               @Nullable Set<? extends Principal> principals) {
        if (!subject.isReadOnly()) {
            subject.getPublicCredentials().add(tc);

            if (principals != null) {
                subject.getPrincipals().addAll(principals);
            }

            if (authInfo != null) {
                setAuthInfo(authInfo, subject);
            }
        }
    }

    @CheckForNull
    private Verifier getVerifier() {
        Verifier v = null;
        SecurityProvider securityProvider = getSecurityProvider();
        if (securityProvider != null) {
            HttpsigConfiguration config = securityProvider.getConfiguration(HttpsigConfiguration.class);
            v = config.getVerifier();
        }
        if (v == null && callbackHandler != null) {
            try {
                VerifierCallback verifierCallback = new VerifierCallback();
                callbackHandler.handle(new Callback[]{verifierCallback});
                v = verifierCallback.getVerifier();
            } catch (IOException e) {
                LOGGER.warn(e.getMessage());
            } catch (UnsupportedCallbackException e) {
                LOGGER.warn(e.getMessage());
            }
        }
        return v;
    }
}
