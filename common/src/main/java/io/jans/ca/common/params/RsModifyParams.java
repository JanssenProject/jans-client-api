package io.jans.ca.common.params;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Strings;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RsModifyParams implements HasRpIdParams {

    @JsonProperty(value = "rp_id")
    private String rp_id;
    @JsonProperty("path")
    String path;
    @JsonProperty("http_method")
    String httpMethod;
    @JsonProperty("scopes")
    List<String> scopes;
    @JsonProperty("scope_expression")
    String scopeExpression;

    public String getRpId() {
        return rp_id;
    }

    public void setRpId(String rpId) {
        this.rp_id = rpId;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public String getScopeExpression() {
        return scopeExpression;
    }

    public void setScopeExpression(String scopeExpression) {
        this.scopeExpression = correctScopeExpression(scopeExpression);
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("RsModifyParams");
        sb.append("{rp_id='").append(rp_id).append('\'');
        sb.append(", path=").append(path);
        sb.append(", httpMethod=").append(httpMethod);
        sb.append(", scopes=").append(scopes);
        sb.append(", scopeExpression=").append(scopeExpression);
        sb.append('}');
        return sb.toString();
    }

    public static String correctScopeExpression(String input) {
        if (!Strings.isNullOrEmpty(input) && !input.equals("null")) {
            return input.replaceAll("'", "\"");//replacing all single quotes to double quotes
        }
        return input;
    }
}
