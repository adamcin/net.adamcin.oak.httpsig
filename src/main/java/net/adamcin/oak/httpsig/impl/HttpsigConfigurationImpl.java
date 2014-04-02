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

import net.adamcin.httpsig.api.Authorization;
import net.adamcin.httpsig.api.Challenge;
import net.adamcin.httpsig.api.Constants;
import net.adamcin.httpsig.api.DefaultKeychain;
import net.adamcin.httpsig.api.DefaultVerifier;
import net.adamcin.httpsig.api.Key;
import net.adamcin.httpsig.api.KeyId;
import net.adamcin.httpsig.api.Keychain;
import net.adamcin.httpsig.api.RequestContent;
import net.adamcin.httpsig.api.Verifier;
import net.adamcin.httpsig.api.VerifyResult;
import net.adamcin.httpsig.ssh.jce.AuthorizedKeys;
import net.adamcin.httpsig.ssh.jce.FingerprintableKey;
import net.adamcin.oak.httpsig.HttpsigConfiguration;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Service;
import org.apache.jackrabbit.oak.spi.security.ConfigurationBase;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.util.Map;

/**
 * Provides a {@link net.adamcin.httpsig.api.DefaultVerifier} for authentication.
 */
@Component
@Service(HttpsigConfiguration.class)
public final class HttpsigConfigurationImpl extends ConfigurationBase implements HttpsigConfiguration {

    private static final Logger LOGGER = LoggerFactory.getLogger(HttpsigConfigurationImpl.class);
    private static final KeyId KEY_ID = new JCRKeyId();

    private String realm;
    private Keychain keychain;
    private DefaultVerifier verifier;
    private Challenge challenge;
    private long skew = DefaultVerifier.DEFAULT_SKEW;

    public HttpsigConfigurationImpl() {
    }

    public HttpsigConfigurationImpl(@Nonnull SecurityProvider securityProvider) {
        super(securityProvider, securityProvider.getParameters(NAME));
    }

    @Activate
    private void activate(Map<String, Object> properties) {
        setParameters(ConfigurationParameters.of(properties));
        this.realm = getParameters().getConfigValue("jaas.realmName", Constants.PREEMPTIVE_CHALLENGE.getRealm());
        this.keychain = loadKeychain();
        this.challenge = new Challenge(this.realm, Constants.DEFAULT_HEADERS, this.keychain.getAlgorithms());
        this.skew = getParameters().getConfigValue(PARAM_SKEW, DefaultVerifier.DEFAULT_SKEW);
        this.verifier = new DefaultVerifier(this.keychain, getKeyId(), this.skew);
    }

    //----------------------------------------------< HttpsigConfiguration >---
    @Override
    public Challenge getChallenge() {
        return this.challenge;
    }

    @Override
    public Verifier getVerifier() {
        return new VerifierGuard();
    }

    //----------------------------------------------< SecurityConfiguration >---
    @Nonnull
    @Override
    public String getName() {
        return NAME;
    }

    //----------------------------------------------< private >---
    private KeyId getKeyId() {
        return KEY_ID;
    }

    private Keychain loadKeychain() {
        DefaultKeychain keychain = new DefaultKeychain();
        for (String param : getParameters().keySet()) {
            if (param.startsWith(PARAM_PREFIX_SSHKEYS)) {
                String userId = param.substring(PARAM_PREFIX_SSHKEYS.length());
                String path = getParameters().getConfigValue(param, "");
                try {
                    Keychain authorizedKeys = AuthorizedKeys.newKeychain(new File(path));
                    if (authorizedKeys != null) {
                        for (Key key : authorizedKeys) {
                            if (key instanceof FingerprintableKey) {
                                keychain.add(new JCRKey(userId, (FingerprintableKey) key));
                            }
                        }
                    }
                } catch (IOException e) {
                    LOGGER.error(String.format("Failed to load authorized_keys file %s for user %s", path, userId), e);
                }
            }
        }

        return keychain;
    }

    private class VerifierGuard implements Verifier {
        @Override
        public long getSkew() {
            return HttpsigConfigurationImpl.this.verifier.getSkew();
        }

        @Override
        public Key selectKey(Authorization authorization) {
            return HttpsigConfigurationImpl.this.verifier.selectKey(authorization);
        }

        @Override
        public boolean verify(Challenge challenge, RequestContent requestContent, Authorization authorization) {
            return HttpsigConfigurationImpl.this.verifier.verify(challenge, requestContent, authorization);
        }

        @Override
        public VerifyResult verifyWithResult(Challenge challenge, RequestContent requestContent, Authorization authorization) {
            return HttpsigConfigurationImpl.this.verifier.verifyWithResult(challenge, requestContent, authorization);
        }
    }
}
