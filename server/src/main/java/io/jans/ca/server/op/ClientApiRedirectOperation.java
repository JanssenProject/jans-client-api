package io.jans.ca.server.op;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.inject.Injector;
import io.jans.as.client.OpenIdConfigurationResponse;
import io.jans.as.client.TokenClient;
import io.jans.as.client.TokenRequest;
import io.jans.as.client.TokenResponse;
import io.jans.as.model.common.AuthenticationMethod;
import io.jans.as.model.common.GrantType;
import io.jans.as.model.common.ResponseType;
import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.jwk.Algorithm;
import io.jans.as.model.jwk.Use;
import io.jans.as.model.jwt.Jwt;
import io.jans.ca.common.Command;
import io.jans.ca.common.ErrorResponseCode;
import io.jans.ca.common.ExpiredObjectType;
import io.jans.ca.common.Jackson2;
import io.jans.ca.common.params.ClientApiRedirectEndpointParams;
import io.jans.ca.common.params.GetAuthorizationUrlParams;
import io.jans.ca.common.response.ClientApiRedirectEndpointResponse;
import io.jans.ca.common.response.IOpResponse;
import io.jans.ca.server.HttpException;
import io.jans.ca.server.service.Rp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class ClientApiRedirectOperation extends BaseOperation<ClientApiRedirectEndpointParams> {
    private static final Logger LOG = LoggerFactory.getLogger(ClientApiRedirectOperation.class);

    /**
     * Base constructor
     *
     * @param command command
     */
    protected ClientApiRedirectOperation(Command command, final Injector injector) {
        super(command, injector, ClientApiRedirectEndpointParams.class);
    }

    @Override
    public IOpResponse execute(ClientApiRedirectEndpointParams params) throws Exception {
        final Rp rp = getRp();

        Set<ResponseType> types = Sets.newHashSet();
        rp.getResponseTypes().forEach(s -> types.addAll(ResponseType.fromString(s, " ")));

        OpenIdConfigurationResponse discoveryResponse = getDiscoveryService().getConnectDiscoveryResponseByRpId(params.getRpId());
        if (types.contains(ResponseType.ID_TOKEN)) {

            if (Strings.isNullOrEmpty(params.getIdToken())) {
                LOG.error("Invalid id_token, null or empty.");
                throw new HttpException(ErrorResponseCode.NO_ID_TOKEN_PARAM);
            }

            final Jwt idToken = Jwt.parse(params.getIdToken());

            final Validator validator = new Validator.Builder()
                    .discoveryResponse(discoveryResponse)
                    .idToken(idToken)
                    .keyService(getKeyService())
                    .opClientFactory(getOpClientFactory())
                    .rpServerConfiguration(getConfigurationService().getConfiguration())
                    .rp(rp)
                    .build();

            //validate at_hash in id_token
            validator.validateAccessToken(params.getAccessToken(), CheckIdTokenOperation.atHashCheckRequired(rp.getResponseTypes()));
            //validate c_hash in id_token
            validator.validateAuthorizationCode(params.getCode());
            //validate s_hash in id_token
            validator.validateState(params.getState());
            //validate id_token
            if (validator.isIdTokenValid(params.getNonce())) {
                LOG.error("Invalid id_token, validation fail due to exception, please check jans_client_api.log for details.");
                throw new HttpException(ErrorResponseCode.INVALID_ID_TOKEN);
            }
        }

        if (types.contains(ResponseType.CODE)) {

            if (Strings.isNullOrEmpty(params.getCode())) {
                LOG.error("Invalid code, null or empty.");
                throw new HttpException(ErrorResponseCode.BAD_REQUEST_NO_CODE);
            }

            final TokenRequest tokenRequest = new TokenRequest(GrantType.AUTHORIZATION_CODE);
            tokenRequest.setCode(params.getCode());
            tokenRequest.setRedirectUri(rp.getRedirectUri());
            tokenRequest.setAuthUsername(rp.getClientId());
            AuthenticationMethod authenticationMethod = AuthenticationMethod.fromString(rp.getTokenEndpointAuthMethod());

            if (authenticationMethod == null) {
                LOG.debug("TokenEndpointAuthMethod is either not set or not valid. Setting `client_secret_basic` as AuthenticationMethod. TokenEndpointAuthMethod : {} ", rp.getTokenEndpointAuthMethod());
                tokenRequest.setAuthenticationMethod(AuthenticationMethod.CLIENT_SECRET_BASIC);
            } else {
                tokenRequest.setAuthenticationMethod(authenticationMethod);
            }

            if (Lists.newArrayList(AuthenticationMethod.PRIVATE_KEY_JWT, AuthenticationMethod.TLS_CLIENT_AUTH, AuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH).contains(authenticationMethod)) {

                Algorithm algorithm = Algorithm.fromString(rp.getTokenEndpointAuthSigningAlg());
                if (algorithm == null) {
                    LOG.error("TokenEndpointAuthSigningAlg is either not set or not valid. TokenEndpointAuthSigningAlg : {} ", rp.getTokenEndpointAuthSigningAlg());
                    throw new HttpException(ErrorResponseCode.INVALID_SIGNATURE_ALGORITHM);
                }

                tokenRequest.setAlgorithm(SignatureAlgorithm.fromString(rp.getTokenEndpointAuthSigningAlg()));

                if (!getConfigurationService().getConfiguration().getEnableJwksGeneration()) {
                    LOG.error("The Token Authentication Method is {}. Please set `enable_jwks_generation` (to `true`), `crypt_provider_key_store_path` and `crypt_provider_key_store_password` in `client-api-server.yml` to enable RP-jwks generation in jans-client-api.", authenticationMethod.toString());
                    throw new HttpException(ErrorResponseCode.JWKS_GENERATION_DISABLE);
                }

                tokenRequest.setCryptoProvider(getKeyGeneratorService().getCryptoProvider());
                tokenRequest.setKeyId(getKeyGeneratorService().getCryptoProvider().getKeyId(getKeyGeneratorService().getKeys(), algorithm, Use.SIGNATURE));
                tokenRequest.setAudience(discoveryResponse.getTokenEndpoint());
            } else {
                tokenRequest.setAuthPassword(rp.getClientSecret());
            }

            final TokenClient tokenClient = getOpClientFactory().createTokenClient(discoveryResponse.getTokenEndpoint());
            tokenClient.setExecutor(getHttpService().getClientExecutor());
            tokenClient.setRequest(tokenRequest);
            final TokenResponse response = tokenClient.exec();

            if (response.getStatus() == 200 || response.getStatus() == 302) { // success or redirect

                if (Strings.isNullOrEmpty(response.getIdToken())) {
                    LOG.error("id_token is not returned. Please check: 1) OP log file for error (oxauth.log) 2) whether 'openid' scope is present for 'get_authorization_url' command");
                    LOG.error("Entity: " + response.getEntity());
                    throw new HttpException(ErrorResponseCode.NO_ID_TOKEN_RETURNED);
                }

                if (Strings.isNullOrEmpty(response.getAccessToken())) {
                    LOG.error("access_token is not returned");
                    throw new HttpException(ErrorResponseCode.NO_ACCESS_TOKEN_RETURNED);
                }

                final Jwt idToken = Jwt.parse(response.getIdToken());

                final Validator validator = new Validator.Builder()
                        .discoveryResponse(discoveryResponse)
                        .idToken(idToken)
                        .keyService(getKeyService())
                        .opClientFactory(getOpClientFactory())
                        .rpServerConfiguration(getConfigurationService().getConfiguration())
                        .rp(rp)
                        .build();

                String state = getStateService().encodeExpiredObject(params.getState(), ExpiredObjectType.STATE);

                validator.validateNonce(getStateService());
                validator.validateIdToken();
                validator.validateAccessToken(response.getAccessToken());
                validator.validateState(state);
                // persist tokens
                rp.setIdToken(response.getIdToken());
                rp.setAccessToken(response.getAccessToken());
                getRpService().update(rp);
                getStateService().deleteExpiredObjectsByKey(state);

                LOG.trace("Scope: " + response.getScope());

                final ClientApiRedirectEndpointResponse opResponse = new ClientApiRedirectEndpointResponse();
                opResponse.setCode(params.getCode());
                opResponse.setAccessToken(response.getAccessToken());
                opResponse.setIdToken(response.getIdToken());
                opResponse.setRefreshToken(response.getRefreshToken());
                opResponse.setExpiresIn(response.getExpiresIn() != null ? response.getExpiresIn() : -1);
                opResponse.setIdTokenClaims(Jackson2.createJsonMapper().readTree(idToken.getClaims().toJsonString()));
                LOG.trace("opResponse: " + opResponse.toString());
                return opResponse;
            } else {
                if (response.getStatus() == 400) {
                    LOG.error("Failed to get tokens because response code is: " + response.getStatus());
                    throw new HttpException(ErrorResponseCode.BAD_REQUEST_INVALID_CODE);
                }
                LOG.error("Failed to get tokens because response code is: " + response.getStatus());
            }
        }
        return null;
    }

    private List<String> acrValues(Rp rp, GetAuthorizationUrlParams params) {
        List<String> acrList = params.getAcrValues() != null && !params.getAcrValues().isEmpty() ? params.getAcrValues() : rp.getAcrValues();
        if (acrList != null) {
            return acrList;
        } else {
            LOG.error("acr value is null for site: " + rp);
            return new ArrayList<>();
        }
    }
}
