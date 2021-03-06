/*
 * jans-api-server
 * jans-api-server
 *
 * OpenAPI spec version: 4.2
 * Contact: yuriyz@gluu.org
 *
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen.git
 * Do not edit the class manually.
 */

package io.swagger.client.model;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.v3.oas.annotations.media.Schema;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/**
 * UmaRpGetClaimsGatheringUrlParams
 */


public class UmaRpGetClaimsGatheringUrlParams {
  @SerializedName("rp_id")
  private String rpId = null;

  @SerializedName("ticket")
  private String ticket = null;

  @SerializedName("state")
  private String state = null;

  @SerializedName("claims_redirect_uri")
  private String claimsRedirectUri = null;

  @SerializedName("custom_parameters")
  private Map<String, String> customParameters = null;

  public UmaRpGetClaimsGatheringUrlParams rpId(String rpId) {
    this.rpId = rpId;
    return this;
  }

   /**
   * Get rpId
   * @return rpId
  **/
  @Schema(example = "bcad760f-91ba-46e1-a020-05e4281d91b6", required = true, description = "")
  public String getRpId() {
    return rpId;
  }

  public void setRpId(String rpId) {
    this.rpId = rpId;
  }

  public UmaRpGetClaimsGatheringUrlParams ticket(String ticket) {
    this.ticket = ticket;
    return this;
  }

   /**
   * Get ticket
   * @return ticket
  **/
  @Schema(example = "fba00191-59ab-4ed6-ac99-a786a88a9f40", required = true, description = "")
  public String getTicket() {
    return ticket;
  }

  public void setTicket(String ticket) {
    this.ticket = ticket;
  }

  public UmaRpGetClaimsGatheringUrlParams state(String state) {
    this.state = state;
    return this;
  }

   /**
   * Get state
   * @return state
  **/
  @Schema(description = "")
  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public UmaRpGetClaimsGatheringUrlParams claimsRedirectUri(String claimsRedirectUri) {
    this.claimsRedirectUri = claimsRedirectUri;
    return this;
  }

   /**
   * Get claimsRedirectUri
   * @return claimsRedirectUri
  **/
  @Schema(example = "https://client.example.com/cb", required = true, description = "")
  public String getClaimsRedirectUri() {
    return claimsRedirectUri;
  }

  public void setClaimsRedirectUri(String claimsRedirectUri) {
    this.claimsRedirectUri = claimsRedirectUri;
  }

  public UmaRpGetClaimsGatheringUrlParams customParameters(Map<String, String> customParameters) {
    this.customParameters = customParameters;
    return this;
  }

  public UmaRpGetClaimsGatheringUrlParams putCustomParametersItem(String key, String customParametersItem) {
    if (this.customParameters == null) {
      this.customParameters = new HashMap<String, String>();
    }
    this.customParameters.put(key, customParametersItem);
    return this;
  }

   /**
   * Get customParameters
   * @return customParameters
  **/
  @Schema(description = "")
  public Map<String, String> getCustomParameters() {
    return customParameters;
  }

  public void setCustomParameters(Map<String, String> customParameters) {
    this.customParameters = customParameters;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UmaRpGetClaimsGatheringUrlParams umaRpGetClaimsGatheringUrlParams = (UmaRpGetClaimsGatheringUrlParams) o;
    return Objects.equals(this.rpId, umaRpGetClaimsGatheringUrlParams.rpId) &&
        Objects.equals(this.ticket, umaRpGetClaimsGatheringUrlParams.ticket) &&
        Objects.equals(this.state, umaRpGetClaimsGatheringUrlParams.state) &&
        Objects.equals(this.claimsRedirectUri, umaRpGetClaimsGatheringUrlParams.claimsRedirectUri) &&
        Objects.equals(this.customParameters, umaRpGetClaimsGatheringUrlParams.customParameters);
  }

  @Override
  public int hashCode() {
    return Objects.hash(rpId, ticket, state, claimsRedirectUri, customParameters);
  }


  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UmaRpGetClaimsGatheringUrlParams {\n");
    
    sb.append("    rpId: ").append(toIndentedString(rpId)).append("\n");
    sb.append("    ticket: ").append(toIndentedString(ticket)).append("\n");
    sb.append("    state: ").append(toIndentedString(state)).append("\n");
    sb.append("    claimsRedirectUri: ").append(toIndentedString(claimsRedirectUri)).append("\n");
    sb.append("    customParameters: ").append(toIndentedString(customParameters)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}
