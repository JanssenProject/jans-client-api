package io.jans.ca.common.params;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 14/03/2017
 */

@JsonIgnoreProperties(ignoreUnknown = true)
public class ValidateParams implements HasRpIdParams {

    @JsonProperty(value = "rp_id")
    private String rp_id;

    @JsonProperty(value = "code")
    private String code;
    @JsonProperty(value = "id_token")
    private String id_token;
    @JsonProperty(value = "access_token")
    private String access_token;

    @JsonProperty(value = "nonce")
    private String nonce;
    @JsonProperty(value = "state")
    private String state;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
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

    public void setAccessToken(String accessToken) {
        this.access_token = accessToken;
    }

    public void setRpId(String rpId) {
        this.rp_id = rpId;
    }

    @Override
    public String getRpId() {
        return rp_id;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    @Override
    public String toString() {
        return "ValidateParams{" +
                "rp_id='" + rp_id + '\'' +
                ", code='" + code + '\'' +
                ", id_token='" + id_token + '\'' +
                ", access_token='" + access_token + '\'' +
                ", nonce='" + nonce + '\'' +
                ", state='" + state + '\'' +
                '}';
    }
}
