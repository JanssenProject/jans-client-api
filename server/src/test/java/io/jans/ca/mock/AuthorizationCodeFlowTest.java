package io.jans.ca.mock;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.Lists;
import io.jans.as.model.common.GrantType;
import io.jans.ca.client.ClientInterface;
import io.jans.ca.client.GetTokensByCodeResponse2;
import io.jans.ca.common.CoreUtils;
import io.jans.ca.common.params.*;
import io.jans.ca.common.response.GetLogoutUriResponse;
import io.jans.ca.common.response.RegisterSiteResponse;
import io.jans.ca.server.Tester;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.util.UUID;

import static org.testng.AssertJUnit.assertNotNull;
import static io.jans.ca.server.TestUtils.notEmpty;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 12/10/2015
 */

public class AuthorizationCodeFlowTest {

    @Parameters({"host", "opHost", "redirectUrls", "userId", "userSecret"})
    @Test
    public void mockTest(String host, String opHost, String redirectUrls, String userId, String userSecret) {
        ClientInterface client = Tester.newClient(host);
         //Register client
        final RegisterSiteResponse site = registerSite(client, opHost, redirectUrls);
        //Get Token by code
        final GetTokensByCodeResponse2 tokens = requestTokens(client, site, userId, userSecret);
        //Get User Info
        GetUserInfoParams params = new GetUserInfoParams();
        params.setRpId(site.getRpId());
        params.setAccessToken(tokens.getAccessToken());

        final JsonNode resp = client.getUserInfo(Tester.getAuthorization(), null, params);
        assertNotNull(resp);
        assertNotNull(resp.get("sub"));

        //Get Logout Url
        getLogoutUrl(client, site, redirectUrls);

    }
    public static RegisterSiteResponse registerSite(ClientInterface client, String opHost, String redirectUrls) {
        return registerSite(client, opHost, redirectUrls, redirectUrls, "");
    }

    public static RegisterSiteResponse registerSite(ClientInterface client, String opHost, String redirectUrls, String postLogoutRedirectUrls, String logoutUri) {

        final RegisterSiteParams params = new RegisterSiteParams();
        params.setOpHost(opHost);
        params.setPostLogoutRedirectUris(Lists.newArrayList(postLogoutRedirectUrls.split(" ")));
        params.setClientFrontchannelLogoutUri(logoutUri);
        params.setRedirectUris(Lists.newArrayList(redirectUrls.split(" ")));
        params.setScope(Lists.newArrayList("openid", "uma_protection", "profile"));
        params.setIdTokenSignedResponseAlg("HS256");
        params.setGrantTypes(Lists.newArrayList(
                GrantType.AUTHORIZATION_CODE.getValue(),
                GrantType.OXAUTH_UMA_TICKET.getValue(),
                GrantType.CLIENT_CREDENTIALS.getValue()));

        final RegisterSiteResponse resp = client.registerSite(params);
        //assertNotNull(resp);
        //assertTrue(!Strings.isNullOrEmpty(resp.getRpId()));
        return resp;
    }
    private GetTokensByCodeResponse2 requestTokens(ClientInterface client, RegisterSiteResponse site, String userId, String userSecret) {

        final String state = CoreUtils.secureRandomString();
        final String nonce = "7r46ut6emu9gi11gn8044um640";

        final GetTokensByCodeParams params = new GetTokensByCodeParams();
        params.setRpId(site.getRpId());
        params.setCode(codeRequest(client, site.getRpId(), userId, userSecret, state, nonce));
        params.setState(state);

        final GetTokensByCodeResponse2 resp = client.getTokenByCode(Tester.getAuthorization(), null, params);
        assertNotNull(resp);
        notEmpty(resp.getAccessToken());
        notEmpty(resp.getIdToken());
        return resp;
    }

    public static String codeRequest(ClientInterface client, String siteId, String userId, String userSecret, String state, String nonce) {
        GetAuthorizationCodeParams params = new GetAuthorizationCodeParams();
        params.setRpId(siteId);
        params.setUsername(userId);
        params.setPassword(userSecret);
        params.setState(state);
        params.setNonce(nonce);

        return client.getAuthorizationCode(Tester.getAuthorization(), null, params).getCode();
    }

    public static void getLogoutUrl(ClientInterface client, RegisterSiteResponse site, String postLogoutRedirectUrl) {
        final GetLogoutUrlParams logoutParams = new GetLogoutUrlParams();
        logoutParams.setRpId(site.getRpId());
        logoutParams.setIdTokenHint("dummy_token");
        logoutParams.setPostLogoutRedirectUri(postLogoutRedirectUrl);
        logoutParams.setState(UUID.randomUUID().toString());
        logoutParams.setSessionState(UUID.randomUUID().toString()); // here must be real session instead of dummy UUID

        final GetLogoutUriResponse resp = client.getLogoutUri(Tester.getAuthorization(), null, logoutParams);
        assertNotNull(resp);
    }
}
