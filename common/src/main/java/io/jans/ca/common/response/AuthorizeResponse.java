package io.jans.ca.common.response;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuthorizeResponse implements IOpResponse {
    @JsonProperty(value = "authorization_url")
    private String authorizationUrl;

    public AuthorizeResponse() {
    }

    public AuthorizeResponse(String authorizationUrl) {
        this.authorizationUrl = authorizationUrl;
    }

    public String getAuthorizationUrl() {
        return authorizationUrl;
    }

    public void setAuthorizationUrl(String authorizationUrl) {
        this.authorizationUrl = authorizationUrl;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("AuthorizeResponse");
        sb.append("{authorizationUrl='").append(authorizationUrl).append('\'');
        sb.append('}');
        return sb.toString();
    }

}
