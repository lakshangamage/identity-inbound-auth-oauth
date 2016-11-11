/*
 *  Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oidc.handler;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.framework.authentication.context.AuthenticationContext;
import org.wso2.carbon.identity.framework.authentication.processor.request.ClientAuthenticationRequest;
import org.wso2.carbon.identity.oauth2poc.exception.OAuth2RuntimeException;
import org.wso2.carbon.identity.oauth2poc.model.AccessToken;
import org.wso2.carbon.identity.oidc.bean.message.request.authz.OIDCAuthzRequest;
import org.wso2.carbon.identity.oidc.exception.OIDCInternalException;
import org.wso2.carbon.identity.oidc.exception.OIDCRuntimeException;

import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class IDTokenHandler extends AbstractIdentityMessageHandler {

    private static final String SHA512_WITH_RSA = "SHA512withRSA";
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<Integer, Key>();
    private static Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();

    @Override
    public String getName() {
        return "IDTokenHandler";
    }

    public JWT buildIDToken(AuthenticationContext messageContext) throws OIDCInternalException {

        ClientAuthenticationRequest request = (ClientAuthenticationRequest)messageContext.getInitialAuthenticationRequest();
        if(request instanceof OIDCAuthzRequest) {
            return buildIDToken((OIDCAuthzRequest)request, messageContext);
        } else {
            throw OAuth2RuntimeException.error("Invalid OAuth2MessageContext - unknown sub type");
        }
    }

    protected JWT buildIDToken(OIDCAuthzRequest request, AuthenticationContext messageContext)
            throws OIDCInternalException {

        String issuer = "https://localhost:9443/oauth2/token";
        long lifetimeInMillis = Integer.parseInt("300") * 1000;
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();
        String subject = messageContext.getSubjectUser().getUserIdentifier();

        AccessToken accessToken = (AccessToken)messageContext.getParameter("AccessToken");
        long accessTokenIssuedTime = accessToken.getAccessTokenIssuedTime().getTime();

        String atHash = null;
        String digAlg = SHA512_WITH_RSA;
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(digAlg);
        } catch (NoSuchAlgorithmException e) {
            throw OIDCInternalException.error("Invalid Algorithm : " + digAlg);
        }
        md.update(accessToken.getAccessToken().getBytes(Charsets.UTF_8));
        byte[] digest = md.digest();

        int leftHalfBytes = 32;

        byte[] leftmost = new byte[leftHalfBytes];
        for (int i = 0; i < leftHalfBytes; i++) {
            leftmost[i] = digest[i];
        }
        atHash = new String(Base64.encodeBase64URLSafe(leftmost), Charsets.UTF_8);

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setSubject(subject);
        jwtClaimsSet.setAudience(Arrays.asList(request.getClientId()));
        jwtClaimsSet.setClaim("azp", request.getClientId());
        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + lifetimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));
        jwtClaimsSet.setClaim("auth_time", accessTokenIssuedTime);
        jwtClaimsSet.setClaim("at_hash", atHash);
        jwtClaimsSet.setClaim("nonce", request.getNonce());

        return signJWTWithRSA(jwtClaimsSet, request);
    }

    protected JWT signJWTWithRSA(JWTClaimsSet jwtClaimsSet, OIDCAuthzRequest request) {
        try {

            int tenantId = IdentityTenantUtil.getTenantId(request.getTenantDomain());

            Key privateKey;

            if (!(privateKeys.containsKey(tenantId))) {

                try {
                    IdentityTenantUtil.initializeRegistry(tenantId, request.getTenantDomain());
                } catch (IdentityException e) {
                    throw OAuth2RuntimeException.error("Error occurred while loading registry for tenant " +
                                                   request.getTenantDomain(), e);
                }

                // get tenant's key store manager
                KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

                if (!request.getTenantDomain().equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                    // derive key store name
                    String ksName = request.getTenantDomain().trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    // obtain private key
                    privateKey = tenantKSM.getPrivateKey(jksName, request.getTenantDomain());

                } else {
                    try {
                        privateKey = tenantKSM.getDefaultPrivateKey();
                    } catch (Exception e) {
                        throw OAuth2RuntimeException.error("Error while obtaining private key for super tenant", e);
                    }
                }
                //privateKey will not be null always
                privateKeys.put(tenantId, privateKey);
            } else {
                //privateKey will not be null because containsKey() true says given key is exist and ConcurrentHashMap
                // does not allow to store null values
                privateKey = privateKeys.get(tenantId);
            }
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            JWSHeader header = new JWSHeader(new JWSAlgorithm(SHA512_WITH_RSA));
            header.setX509CertThumbprint(new Base64URL(getThumbPrint(request.getTenantDomain(), tenantId)));
            SignedJWT signedJWT = new SignedJWT(header, jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            throw OAuth2RuntimeException.error("Error occurred while signing JWT", e);
        }
    }

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param tenantDomain
     * @param tenantId
     */
    private String getThumbPrint(String tenantDomain, int tenantId) {

        try {

            Certificate certificate = getCertificate(tenantDomain, tenantId);

            // TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization

            //generate the SHA-1 thumbprint of the certificate
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            byte[] der = certificate.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();

            String publicCertThumbprint = hexify(digestInBytes);
            String base64EncodedThumbPrint = new String(new Base64(0, null, true).encode(
                    publicCertThumbprint.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
            return base64EncodedThumbPrint;

        } catch (Exception e) {
            String error = "Error in obtaining certificate for tenant " + tenantDomain;
            throw OIDCRuntimeException.error(error, e);
        }
    }

    private Certificate getCertificate(String tenantDomain, int tenantId) throws Exception {

        if (tenantDomain == null) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        if (tenantId == 0) {
            tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        }

        Certificate publicCert = null;

        if (!(publicCerts.containsKey(tenantId))) {

            try {
                IdentityTenantUtil.initializeRegistry(tenantId, tenantDomain);
            } catch (IdentityException e) {
                throw OIDCRuntimeException.error("Error occurred while loading registry for tenant " + tenantDomain, e);
            }

            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            KeyStore keyStore = null;
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                keyStore = tenantKSM.getKeyStore(jksName);
                publicCert = keyStore.getCertificate(tenantDomain);
            } else {
                publicCert = tenantKSM.getDefaultPrimaryCertificate();
            }
            if (publicCert != null) {
                publicCerts.put(tenantId, publicCert);
            }
        } else {
            publicCert = publicCerts.get(tenantId);
        }
        return publicCert;
    }

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes
     * @return  hexadecimal representation
     */
    private String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                            +                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }
}
