package io.jans.ca.common.params;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.jans.ca.common.Jackson2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthorizeParams implements HasRpIdParams {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizeParams.class);

    @JsonProperty(value = "rp_id")
    private String rp_id;
    @JsonProperty(value = "acr_values")
    private List<String> acr_values;
    @JsonProperty(value = "prompt")
    private String prompt;
    @JsonProperty(value = "scope")
    private List<String> scope;
    @JsonProperty(value = "hd")
    private String hd; // https://developers.google.com/identity/protocols/OpenIDConnect#hd-param
    @JsonProperty(value = "state")
    private String state;
    @JsonProperty(value = "nonce")
    private String nonce;
    @JsonProperty(value = "custom_parameters")
    private Map<String, String> custom_parameters;
    @JsonProperty(value = "params")
    private Map<String, String> params;
    @JsonProperty(value = "redirect_uri")
    private String redirect_uri;
    @JsonProperty(value = "response_types")
    private List<String> response_types;

    public AuthorizeParams() {
    }

    public AuthorizeParams(String rpId, List<String> acrValues, List<String> scope, String state, String nonce, String redirectUri, List<String> responseTypes) {
        this.rp_id = rpId;
        this.acr_values = acrValues;
        this.scope = scope;
        this.state = state;
        this.nonce = nonce;
        this.redirect_uri = redirectUri;
        this.response_types = responseTypes;
    }

    public Map<String, String> getCustomParameters() {
        return custom_parameters;
    }

    public void setCustomParameters(Map<String, String> customParameters) {
        this.custom_parameters = customParameters;
    }

    public String getHostedDomain() {
        return hd;
    }

    public void setHostedDomain(String hostedDomain) {
        this.hd = hostedDomain;
    }

    public List<String> getScope() {
        return scope;
    }

    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    public String getPrompt() {
        return prompt;
    }

    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    public String getRpId() {
        return rp_id;
    }

    public void setRpId(String rpId) {
        this.rp_id = rpId;
    }

    public List<String> getAcrValues() {
        return acr_values;
    }

    public void setAcrValues(List<String> acrValues) {
        this.acr_values = acrValues;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public void setParams(Map<String, String> params) {
        this.params = params;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getRedirectUri() {
        return redirect_uri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirect_uri = redirectUri;
    }

    public List<String> getResponseTypes() {
        return response_types;
    }

    public void setResponseTypes(List<String> responseTypes) {
        this.response_types = responseTypes;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizeParams that = (AuthorizeParams) o;
        return Objects.equals(rp_id, that.rp_id) &&
                Objects.equals(acr_values, that.acr_values);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rp_id, acr_values);
    }

    @Override
    public String toString() {
        return "AuthorizeParams{" +
                "rp_id='" + rp_id + '\'' +
                ", acr_values=" + acr_values +
                ", prompt='" + prompt + '\'' +
                ", scope=" + scope +
                ", hd='" + hd + '\'' +
                ", params=" + params +
                ", custom_parameters=" + custom_parameters +
                ", redirect_uri='" + redirect_uri + '\'' +
                ", state='" + state + '\'' +
                ", nonce='" + nonce + '\'' +
                ", response_types=" + response_types + '\'' +
                '}';
    }

    public String toJsonString() {
        try {
            return Jackson2.serializeWithoutNulls(this);
        } catch (IOException e) {
            LOG.error("Error in parsing StringParam object.", e);
            throw new RuntimeException(e);
        }
    }
}
