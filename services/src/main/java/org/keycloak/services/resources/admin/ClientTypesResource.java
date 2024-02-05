/*
 * Copyright 2021 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.services.resources.admin;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.extensions.Extension;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.ClientTypesRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.client.clienttype.ClientTypeException;
import org.keycloak.client.clienttype.ClientTypeManager;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Extension(name = KeycloakOpenAPI.Profiles.ADMIN, value = "")
public class ClientTypesResource {
    protected static final Logger logger = Logger.getLogger(ClientTypesResource.class);

    protected final HttpRequest request;

    protected final HttpResponse response;

    protected final KeycloakSession session;

    protected final RealmModel realm;
    private final AdminPermissionEvaluator auth;

    public ClientTypesResource(KeycloakSession session, AdminPermissionEvaluator auth) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.auth = auth;
        this.request = session.getContext().getHttpRequest();
        this.response = session.getContext().getHttpResponse();
    }

    @GET
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.REALMS_ADMIN)
    @Operation()
    public ClientTypesRepresentation getClientTypes() {
        auth.realm().requireViewRealm();

        try {
            return session.getProvider(ClientTypeManager.class).getClientTypes(realm);
        } catch (ClientTypeException e) {
            logger.error(e.getMessage(), e);
            throw new BadRequestException(ErrorResponse.error(e.getMessage(), Response.Status.BAD_REQUEST));
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.REALMS_ADMIN)
    @Operation()
    public Response updateClientTypes(final ClientTypesRepresentation clientTypes) {
        auth.realm().requireManageRealm();

        try {
            session.getProvider(ClientTypeManager.class).updateClientTypes(realm, clientTypes);
        } catch (ClientTypeException e) {
            logger.error(e.getMessage(), e);
            throw ErrorResponse.error(e.getMessage(), Response.Status.BAD_REQUEST);
        }
        return Response.noContent().build();
    }
}