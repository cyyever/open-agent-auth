/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ai.shao.openagentauth.core.model.identity;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Represents the identity of an AI agent.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AgentIdentity(
        @JsonProperty("version") String version,
        @JsonProperty("id") String id,
        @JsonProperty("issuer") String issuer,
        @JsonProperty("issued_to") String issuedTo,
        @JsonProperty("issued_for") IssuedFor issuedFor,
        @JsonProperty("issuance_date") Instant issuanceDate,
        @JsonProperty("valid_from") Instant validFrom,
        @JsonProperty("expires") Instant expires) {

    public static Builder builder() {
        return new Builder();
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record IssuedFor(
            @JsonProperty("platform") String platform,
            @JsonProperty("client") String client,
            @JsonProperty("client_instance") String clientInstance) {

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String platform;
            private String client;
            private String clientInstance;

            public Builder platform(String platform)             { this.platform = platform;             return this; }
            public Builder client(String client)                 { this.client = client;                 return this; }
            public Builder clientInstance(String clientInstance) { this.clientInstance = clientInstance; return this; }

            public IssuedFor build() {
                return new IssuedFor(platform, client, clientInstance);
            }
        }
    }

    public static class Builder {
        private String version = "1.0";
        private String id;
        private String issuer;
        private String issuedTo;
        private IssuedFor issuedFor;
        private Instant issuanceDate;
        private Instant validFrom;
        private Instant expires;

        public Builder version(String version)             { this.version = version;           return this; }
        public Builder id(String id)                       { this.id = id;                     return this; }
        public Builder issuer(String issuer)               { this.issuer = issuer;             return this; }
        public Builder issuedTo(String issuedTo)           { this.issuedTo = issuedTo;         return this; }
        public Builder issuedFor(IssuedFor issuedFor)      { this.issuedFor = issuedFor;       return this; }
        public Builder issuanceDate(Instant issuanceDate)  { this.issuanceDate = issuanceDate; return this; }
        public Builder validFrom(Instant validFrom)        { this.validFrom = validFrom;       return this; }
        public Builder expires(Instant expires)            { this.expires = expires;           return this; }

        public AgentIdentity build() {
            return new AgentIdentity(version, id, issuer, issuedTo, issuedFor, issuanceDate, validFrom, expires);
        }
    }
}
