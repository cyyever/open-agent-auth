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
package com.alibaba.openagentauth.core.model.identity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Objects;

/**
 * Represents the identity of an AI agent.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AgentIdentity {

    /**
     * Version of the agent identity structure.
     */
    @JsonProperty("version")
    private final String version;

    /**
     * Unique identifier for this agent instance.
     */
    @JsonProperty("id")
    private final String id;

    /**
     * URI identifying the entity that issued this agent identity.
     */
    @JsonProperty("issuer")
    private final String issuer;

    /**
     * Unique identifier for the human principal this agent is authorized to act on behalf of.
     */
    @JsonProperty("issued_to")
    private final String issuedTo;

    /**
     * Deployment context (platform, client, client instance).
     */
    @JsonProperty("issued_for")
    private final IssuedFor issuedFor;

    /**
     * Date when this identity was issued.
     */
    @JsonProperty("issuance_date")
    private final Instant issuanceDate;

    /**
     * Date from which this identity is valid.
     */
    @JsonProperty("valid_from")
    private final Instant validFrom;

    /**
     * Expiration date of this identity.
     */
    @JsonProperty("expires")
    private final Instant expires;

    /**
     * Constructor for Jackson deserialization.
     */
    @JsonCreator
    public AgentIdentity(
            @JsonProperty("version") String version,
            @JsonProperty("id") String id,
            @JsonProperty("issuer") String issuer,
            @JsonProperty("issued_to") String issuedTo,
            @JsonProperty("issued_for") IssuedFor issuedFor,
            @JsonProperty("issuance_date") Instant issuanceDate,
            @JsonProperty("valid_from") Instant validFrom,
            @JsonProperty("expires") Instant expires
    ) {
        this.version = version;
        this.id = id;
        this.issuer = issuer;
        this.issuedTo = issuedTo;
        this.issuedFor = issuedFor;
        this.issuanceDate = issuanceDate;
        this.validFrom = validFrom;
        this.expires = expires;
    }

    private AgentIdentity(Builder builder) {
        this.version = builder.version;
        this.id = builder.id;
        this.issuer = builder.issuer;
        this.issuedTo = builder.issuedTo;
        this.issuedFor = builder.issuedFor;
        this.issuanceDate = builder.issuanceDate;
        this.validFrom = builder.validFrom;
        this.expires = builder.expires;
    }

    /**
     * Gets the agent version.
     *
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Gets the unique agent identifier.
     *
     * @return the agent ID
     */
    public String getId() {
        return id;
    }

    /**
     * Gets the issuer of this agent identity.
     *
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Gets the user ID this agent is issued to.
     *
     * @return the user ID
     */
    public String getIssuedTo() {
        return issuedTo;
    }

    /**
     * Gets the context for which this agent identity was issued.
     *
     * @return the issued for context
     */
    public IssuedFor getIssuedFor() {
        return issuedFor;
    }

    /**
     * Gets the date when this identity was issued.
     *
     * @return the issuance date
     */
    public Instant getIssuanceDate() {
        return issuanceDate;
    }

    /**
     * Gets the date from which this identity is valid.
     *
     * @return the valid from date
     */
    public Instant getValidFrom() {
        return validFrom;
    }

    /**
     * Gets the expiration date of this identity.
     *
     * @return the expiration date
     */
    public Instant getExpires() {
        return expires;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AgentIdentity that = (AgentIdentity) o;
        return Objects.equals(version, that.version) &&
               Objects.equals(id, that.id) &&
               Objects.equals(issuer, that.issuer) &&
               Objects.equals(issuedTo, that.issuedTo) &&
               Objects.equals(issuedFor, that.issuedFor) &&
               Objects.equals(issuanceDate, that.issuanceDate) &&
               Objects.equals(validFrom, that.validFrom) &&
               Objects.equals(expires, that.expires);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, id, issuer, issuedTo, issuedFor, issuanceDate, validFrom, expires);
    }

    @Override
    public String toString() {
        return "AgentIdentity{" +
                "version='" + version + '\'' +
                ", id='" + id + '\'' +
                ", issuer='" + issuer + '\'' +
                ", issuedTo='" + issuedTo + '\'' +
                ", issuedFor=" + issuedFor +
                ", issuanceDate=" + issuanceDate +
                ", validFrom=" + validFrom +
                ", expires=" + expires +
                '}';
    }

    /**
     * Creates a new builder for {@link AgentIdentity}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Deployment context (platform, client, client instance).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class IssuedFor {

        /**
         * Platform identifier.
         */
        @JsonProperty("platform")
        private final String platform;

        /**
         * Client identifier.
         */
        @JsonProperty("client")
        private final String client;

        /**
         * Client instance identifier.
         */
        @JsonProperty("client_instance")
        private final String clientInstance;

        /**
         * Constructor for Jackson deserialization.
         */
        @JsonCreator
        public IssuedFor(
                @JsonProperty("platform") String platform,
                @JsonProperty("client") String client,
                @JsonProperty("client_instance") String clientInstance) {
            this.platform = platform;
            this.client = client;
            this.clientInstance = clientInstance;
        }

        private IssuedFor(Builder builder) {
            this.platform = builder.platform;
            this.client = builder.client;
            this.clientInstance = builder.clientInstance;
        }

        /**
         * Gets the platform.
         *
         * @return the platform
         */
        public String getPlatform() {
            return platform;
        }

        /**
         * Gets the client.
         *
         * @return the client
         */
        public String getClient() {
            return client;
        }

        /**
         * Gets the client instance.
         *
         * @return the client instance
         */
        public String getClientInstance() {
            return clientInstance;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            IssuedFor issuedFor = (IssuedFor) o;
            return Objects.equals(platform, issuedFor.platform) &&
                   Objects.equals(client, issuedFor.client) &&
                   Objects.equals(clientInstance, issuedFor.clientInstance);
        }

        @Override
        public int hashCode() {
            return Objects.hash(platform, client, clientInstance);
        }

        @Override
        public String toString() {
            return "IssuedFor{" +
                    "platform='" + platform + '\'' +
                    ", client='" + client + '\'' +
                    ", clientInstance='" + clientInstance + '\'' +
                    '}';
        }

        /**
         * Creates a new builder for {@link IssuedFor}.
         *
         * @return a new builder instance
         */
        public static Builder builder() {
            return new Builder();
        }

        /**
         * Builder for {@link IssuedFor}.
         */
        public static class Builder {
            private String platform;
            private String client;
            private String clientInstance;

            /**
             * Sets the platform.
             *
             * @param platform the platform
             * @return this builder instance
             */
            public Builder platform(String platform) {
                this.platform = platform;
                return this;
            }

            /**
             * Sets the client.
             *
             * @param client the client
             * @return this builder instance
             */
            public Builder client(String client) {
                this.client = client;
                return this;
            }

            /**
             * Sets the client instance.
             *
             * @param clientInstance the client instance
             * @return this builder instance
             */
            public Builder clientInstance(String clientInstance) {
                this.clientInstance = clientInstance;
                return this;
            }

            /**
             * Builds the {@link IssuedFor}.
             *
             * @return the built object
             */
            public IssuedFor build() {
                return new IssuedFor(this);
            }
        }
    }

    /**
     * Builder for {@link AgentIdentity}.
     */
    public static class Builder {
        private String version = "1.0";
        private String id;
        private String issuer;
        private String issuedTo;
        private IssuedFor issuedFor;
        private Instant issuanceDate;
        private Instant validFrom;
        private Instant expires;

        /**
         * Sets the version.
         *
         * @param version the version
         * @return this builder instance
         */
        public Builder version(String version) {
            this.version = version;
            return this;
        }

        /**
         * Sets the agent ID.
         *
         * @param id the agent ID
         * @return this builder instance
         */
        public Builder id(String id) {
            this.id = id;
            return this;
        }

        /**
         * Sets the issuer.
         *
         * @param issuer the issuer
         * @return this builder instance
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /**
         * Sets the user ID this agent is issued to.
         *
         * @param issuedTo the user ID
         * @return this builder instance
         */
        public Builder issuedTo(String issuedTo) {
            this.issuedTo = issuedTo;
            return this;
        }

        /**
         * Sets the issued for context.
         *
         * @param issuedFor the issued for context
         * @return this builder instance
         */
        public Builder issuedFor(IssuedFor issuedFor) {
            this.issuedFor = issuedFor;
            return this;
        }

        /**
         * Sets the issuance date.
         *
         * @param issuanceDate the issuance date
         * @return this builder instance
         */
        public Builder issuanceDate(Instant issuanceDate) {
            this.issuanceDate = issuanceDate;
            return this;
        }

        /**
         * Sets the valid from date.
         *
         * @param validFrom the valid from date
         * @return this builder instance
         */
        public Builder validFrom(Instant validFrom) {
            this.validFrom = validFrom;
            return this;
        }

        /**
         * Sets the expiration date.
         *
         * @param expires the expiration date
         * @return this builder instance
         */
        public Builder expires(Instant expires) {
            this.expires = expires;
            return this;
        }

        /**
         * Builds the {@link AgentIdentity}.
         *
         * @return the built identity
         */
        public AgentIdentity build() {
            return new AgentIdentity(this);
        }
    }
}