package io.jans.ca.server.op;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.inject.Injector;
import io.jans.as.model.authorize.AuthorizeRequestParam;
import io.jans.as.model.util.Util;
import io.jans.ca.common.Command;
import io.jans.ca.common.ErrorResponseCode;
import io.jans.ca.common.ExpiredObjectType;
import io.jans.ca.common.params.AuthorizeParams;
import io.jans.ca.common.response.AuthorizeResponse;
import io.jans.ca.common.response.IOpResponse;
import io.jans.ca.server.HttpException;
import io.jans.ca.server.Utils;
import io.jans.ca.server.service.Rp;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 22/09/2015
 */

public class AuthorizeOperation extends BaseOperation<AuthorizeParams> {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizeOperation.class);

    /**
     * Base constructor
     *
     * @param command command
     */
    protected AuthorizeOperation(Command command, final Injector injector) {
        super(command, injector, AuthorizeParams.class);
    }

    @Override
    public IOpResponse execute(AuthorizeParams params) throws Exception {
        final Rp rp = getRp();

        String authorizationEndpoint = getDiscoveryService().getConnectDiscoveryResponse(rp).getAuthorizationEndpoint();

        List<String> scope = Lists.newArrayList();
        if (params.getScope() != null && !params.getScope().isEmpty()) {
            scope.addAll(params.getScope());
        } else if (rp.getScope() != null) {
            scope.addAll(rp.getScope());
        }

        if (StringUtils.isNotBlank(params.getRedirectUri()) && !Utils.isValidUrl(params.getRedirectUri())) {
            throw new HttpException(ErrorResponseCode.INVALID_REDIRECT_URI);
        }

        if (StringUtils.isNotBlank(params.getRedirectUri()) && !rp.getRedirectUris().contains(params.getRedirectUri())) {
            throw new HttpException(ErrorResponseCode.REDIRECT_URI_IS_NOT_REGISTERED);
        }

        List<String> responseTypes = Lists.newArrayList();
        if (params.getResponseTypes() != null && !params.getResponseTypes().isEmpty()
                && rp.getResponseTypes().containsAll(params.getResponseTypes())) {
            responseTypes.addAll(params.getResponseTypes());
        } else {
            responseTypes.addAll(rp.getResponseTypes());
        }

        String state = StringUtils.isNotBlank(params.getState()) ? getStateService().putState(getStateService().encodeExpiredObject(params.getState(), ExpiredObjectType.STATE)) : getStateService().generateState();
        String nonce = StringUtils.isNotBlank(params.getNonce()) ? getStateService().putNonce(getStateService().encodeExpiredObject(params.getNonce(), ExpiredObjectType.NONCE)) : getStateService().generateNonce();
        String clientId = getConfigurationService().getConfiguration().getEncodeClientIdInAuthorizationUrl() ? Utils.encode(rp.getClientId()) : rp.getClientId();
        String redirectUri = StringUtils.isNotBlank(params.getRedirectUri()) ? params.getRedirectUri() : rp.getRedirectUri();

        authorizationEndpoint += "?response_type=" + Utils.joinAndUrlEncode(responseTypes);
        authorizationEndpoint += "&client_id=" + clientId;
        authorizationEndpoint += "&redirect_uri=" + redirectUri;
        authorizationEndpoint += "&scope=" + Utils.joinAndUrlEncode(scope);
        authorizationEndpoint += "&state=" + state;
        authorizationEndpoint += "&nonce=" + nonce;

        String acrValues = Utils.joinAndUrlEncode(acrValues(rp, params)).trim();
        if (!Strings.isNullOrEmpty(acrValues)) {
            authorizationEndpoint += "&acr_values=" + acrValues;
        }

        if (!Strings.isNullOrEmpty(params.getPrompt())) {
            authorizationEndpoint += "&prompt=" + params.getPrompt();
        }
        if (!Strings.isNullOrEmpty(params.getHostedDomain())) {
            authorizationEndpoint += "&hd=" + params.getHostedDomain();
        }

        if (params.getCustomParameters() != null && !params.getCustomParameters().isEmpty()) {
            authorizationEndpoint += "&" + AuthorizeRequestParam.CUSTOM_RESPONSE_HEADERS + "=" + Utils.encode(Util.mapAsString(params.getCustomParameters()));
        }

        if (params.getParams() != null && !params.getParams().isEmpty()) {
            authorizationEndpoint += "&" + Utils.mapAsStringWithEncodedValues(params.getParams());
        }

        return new AuthorizeResponse(authorizationEndpoint);
    }

    private List<String> acrValues(Rp rp, AuthorizeParams params) {
        List<String> acrList = params.getAcrValues() != null && !params.getAcrValues().isEmpty() ? params.getAcrValues() : rp.getAcrValues();
        if (acrList != null) {
            return acrList;
        } else {
            LOG.error("acr value is null for site: " + rp);
            return new ArrayList<>();
        }
    }
}
