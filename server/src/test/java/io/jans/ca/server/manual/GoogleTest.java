package io.jans.ca.server.manual;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import io.jans.ca.client.ClientInterface;
import io.jans.ca.common.params.GetAuthorizationUrlParams;
import io.jans.ca.common.params.RegisterSiteParams;
import io.jans.ca.common.response.GetAuthorizationUrlResponse;
import io.jans.ca.common.response.RegisterSiteResponse;
import io.jans.ca.server.Tester;

import static io.jans.ca.server.TestUtils.notEmpty;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertTrue;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 25/08/2016
 */

public class GoogleTest {

    private static final String HOST = "http://localhost:8084";

    private static final String OP_HOST = "https://accounts.google.com";
    private static final String REDIRECT_URI = "https://mytestproduct.com";

    private static final String CLIENT_ID = "";
    private static final String CLIENT_SECRET = "";

    public static void main(String[] args) {
//        ClientInterface client = Tester.newClient(HOST);
//
//        final RegisterSiteResponse site = registerSite(client);
//        final String authorizationUrl = getAuthorizationUrl(client, site.getRpId());

        // after successful login get redirect with code
        // https://mytestproduct.com/?state=af0ifjsldkj&code=4/2I5U130cxs7MObKVniVseBQkHQ0JQS0p5JfZm7NgZ-M&authuser=0&session_state=02bd0461002924877bee444d9dfd9f1279e44335..ae63&prompt=consent#
//            String code = "4/2I5U130cxs7MObKVniVseBQkHQ0JQS0p5JfZm7NgZ-M";
//            String code = "4/e8WrOQDMNRllHvMGAEKAovwWMnIy7k7oxRN4Xn9JPrg";
//        String code = "4/nWqDxBS-c7MDN_1Gq2WtW2L6B9KnA5rpOOYzGEdg7lM";
//
//        final GetTokensByCodeParams params = new GetTokensByCodeParams();
//        params.setRpId(site.getRpId());
//        params.setCode(code);
//
//        final GetTokensByCodeResponse resp = client.getTokenByCode(Tester.getAuthorization(), params);
//        System.out.println(resp);
    }

    private static String getAuthorizationUrl(ClientInterface client, RegisterSiteResponse site) {
        final GetAuthorizationUrlParams params = new GetAuthorizationUrlParams();
        params.setRpId(site.getRpId());

        final GetAuthorizationUrlResponse resp = client.getAuthorizationUrl(Tester.getAuthorization(site), null, params);
        assertNotNull(resp);
        notEmpty(resp.getAuthorizationUrl());
        System.out.println("Authorization url: " + resp.getAuthorizationUrl());
        return resp.getAuthorizationUrl();
    }

    public static RegisterSiteResponse registerSite(ClientInterface client) {

        final RegisterSiteParams params = new RegisterSiteParams();
        params.setOpHost(OP_HOST);
        params.setRedirectUris(Lists.newArrayList(REDIRECT_URI));
        params.setClientId(CLIENT_ID);
        params.setClientSecret(CLIENT_SECRET);

        final RegisterSiteResponse resp = client.registerSite(params);
        assertNotNull(resp);
        assertTrue(!Strings.isNullOrEmpty(resp.getRpId()));
        return resp;
    }
}
