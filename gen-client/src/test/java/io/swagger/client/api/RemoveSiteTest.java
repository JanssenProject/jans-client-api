package io.swagger.client.api;

import io.swagger.client.ApiException;
import io.swagger.client.model.RegisterSiteResponse;
import io.swagger.client.model.RemoveSiteParams;
import io.swagger.client.model.RemoveSiteResponse;
import org.apache.commons.lang.StringUtils;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import io.jans.ca.common.ErrorResponseCode;

import java.util.UUID;

import static org.testng.Assert.*;

public class RemoveSiteTest {

    @Test
    @Parameters({"opHost", "redirectUrls"})
    public void testRemoveSite(String opHost, String redirectUrls) throws Exception {
        final DevelopersApi api = Tester.api();
        RegisterSiteResponse response = RegisterSiteTest.registerSite(api, opHost, redirectUrls);

        RemoveSiteParams params = new RemoveSiteParams();
        params.setRpId(response.getRpId());

        RemoveSiteResponse removeResponse = api.removeSite(params, Tester.getAuthorization(response), null);
        assertNotNull(removeResponse);
        assertTrue(StringUtils.isNotEmpty(removeResponse.getRpId()));
    }

    @Test
    public void testRemoveSiteWithInvalidRpId() throws Exception {
        final String someRandomId = UUID.randomUUID().toString();
        final DevelopersApi api = Tester.api();

        RemoveSiteParams params = new RemoveSiteParams();
        params.setRpId(someRandomId);
        try {
            api.removeSite(params, Tester.getAuthorization(), null);
        } catch (ApiException e) {
            assertEquals(e.getCode(), 400);
            assertEquals(Tester.asError(e).getError(), ErrorResponseCode.INVALID_RP_ID.getCode());
            return;
        }
        throw new AssertionError("Expected 400 error but got successful result.");
    }
}
