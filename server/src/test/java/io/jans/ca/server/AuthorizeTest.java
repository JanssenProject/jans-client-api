package io.jans.ca.server;

import io.jans.as.client.AuthorizationResponse;
import io.jans.as.model.common.GrantType;
import io.jans.ca.client.ClientInterface;
import io.jans.ca.common.CoreUtils;
import io.jans.ca.common.SeleniumTestUtils;
import io.jans.ca.common.params.AuthorizeParams;
import io.jans.ca.common.params.RegisterSiteParams;
import io.jans.ca.common.response.RegisterSiteResponse;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.CloseableHttpClient;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.testng.collections.Lists;

import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.testng.AssertJUnit.assertNotNull;

public class AuthorizeTest {
    @Parameters({"host", "redirectUrls", "opHost"})
    @Test
    public void test(String host, String redirectUrls, String opHost) throws Exception {
        ClientInterface client = Tester.newClient(host);

        final RegisterSiteParams params = new RegisterSiteParams();
        params.setOpHost(opHost);
        params.setRedirectUris(Lists.newArrayList(host + ":8443/client-api-redirect-endpoint"));
        params.setScope(com.google.common.collect.Lists.newArrayList("openid", "uma_protection", "profile", "jans_client_api"));
        params.setResponseTypes(com.google.common.collect.Lists.newArrayList("code", "id_token", "token"));
        params.setGrantTypes(com.google.common.collect.Lists.newArrayList(
                GrantType.AUTHORIZATION_CODE.getValue(),
                GrantType.OXAUTH_UMA_TICKET.getValue(),
                GrantType.CLIENT_CREDENTIALS.getValue()));

        final RegisterSiteResponse resp = client.registerSite(params);

        AuthorizeParams authorizeParams = new AuthorizeParams();
        authorizeParams.setRpId(resp.getRpId());
        authorizeParams.setScope(Lists.newArrayList("openid", "oxd"));
        authorizeParams.setAcrValues(Lists.newArrayList("basic"));

        Response response = client.authorize(Tester.getAuthorization(resp), null, authorizeParams);
        assertNotNull(response.getLocation());
    }
}
