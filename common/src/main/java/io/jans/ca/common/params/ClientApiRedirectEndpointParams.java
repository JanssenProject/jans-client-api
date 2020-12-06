package io.jans.ca.common.params;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.jans.ca.common.Jackson2;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientApiRedirectEndpointParams implements HasRpIdParams {
    private static final Logger LOG = LoggerFactory.getLogger(ClientApiRedirectEndpointParams.class);

    @JsonProperty(value = "rp_id")
    private String rp_id;
    @JsonProperty(value = "code")
    private String code;
    @JsonProperty(value = "id_token")
    private String id_token;
    @JsonProperty(value = "access_token")
    private String access_token;
    @JsonProperty(value = "state")
    private String state;
    @JsonProperty(value = "nonce")
    private String nonce;

    public ClientApiRedirectEndpointParams() {

    }

    public ClientApiRedirectEndpointParams(String rpId, String code, String idToken, String accessToken, String state) {
        this.rp_id = rpId;
        this.code = code;
        this.id_token = idToken;
        this.access_token = accessToken;
        this.state = state;
        this.nonce = nonce;
    }

    public String getRpId() {
        return rp_id;
    }

    public void setRpId(String rpId) {
        this.rp_id = rpId;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getIdToken() {
        return id_token;
    }

    public void setIdToken(String idToken) {
        this.id_token = idToken;
    }

    public String getAccessToken() {
        return access_token;
    }

    public void setAccessToken(String access_token) {
        this.access_token = access_token;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    @Override
    public String toString() {
        return "ClientApiRedirectEndpoint{" +
                "rp_id='" + rp_id + '\'' +
                ", code='" + code + '\'' +
                ", id_token='" + id_token + '\'' +
                ", access_token='" + access_token + '\'' +
                ", state='" + state + '\'' +
                ", nonce='" + nonce + '\'' +
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
