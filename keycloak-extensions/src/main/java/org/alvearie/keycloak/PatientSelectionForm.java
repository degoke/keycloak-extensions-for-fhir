/*
(C) Copyright IBM Corp. 2021

SPDX-License-Identifier: Apache-2.0
*/
package org.alvearie.keycloak;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.alvearie.keycloak.freemarker.PatientStruct;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.sessions.AuthenticationSessionModel;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.api.MethodOutcome;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.interceptor.BearerTokenAuthInterceptor;
import ca.uhn.fhir.rest.server.exceptions.BaseServerResponseException;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.HumanName;
import org.hl7.fhir.r4.model.Patient;
import org.hl7.fhir.r4.model.Bundle.BundleEntryComponent;
import org.hl7.fhir.r4.model.Bundle.BundleEntryRequestComponent;
import org.hl7.fhir.r4.model.Bundle.BundleType;
import org.hl7.fhir.r4.model.Bundle.HTTPVerb;

/**
 * Present a patient context picker when the client requests the launch/patient scope and the
 * user record has multiple resourceId attributes. The selection is stored in a UserSessionNote
 * with name "patient_id".
 */
public class PatientSelectionForm implements Authenticator {

    private static final Logger LOG = Logger.getLogger(PatientSelectionForm.class);

    private static final String SMART_AUDIENCE_PARAM = "client_request_param_aud";
    private static final String SMART_SCOPE_PATIENT_READ = "patient/Patient.read";
    private static final String SMART_SCOPE_LAUNCH_PATIENT = "launch/patient";

    private static final String ATTRIBUTE_RESOURCE_ID = "resourceId";

    private FhirContext fhirContext;

    public PatientSelectionForm() {
        fhirContext = FhirContext.forR4();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        ClientModel client = authSession.getClient();

        String requestedScopesString = authSession.getClientNote(OIDCLoginProtocol.SCOPE_PARAM);
        Stream<ClientScopeModel> clientScopes = TokenManager.getRequestedClientScopes(context.getSession(), requestedScopesString, client, context.getUser());

        if (clientScopes.noneMatch(s -> SMART_SCOPE_LAUNCH_PATIENT.equals(s.getName()))) {
            // no launch/patient scope == no-op
            context.success();
            return;
        }

        if (context.getUser() == null) {
            fail(context, "Expected a user but found null");
            return;
        }

        List<String> resourceIds = getResourceIdsForUser(context);
        if (resourceIds.size() == 0) {
            fail(context, "Expected user to have one or more resourceId attributes, but found none");
            return;
        }
        if (resourceIds.size() == 1) {
            succeed(context, resourceIds.get(0));
            return;
        }

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || !config.getConfig().containsKey(PatientSelectionFormFactory.INTERNAL_FHIR_URL_PROP_NAME)) {
            fail(context, "The Patient Selection Authenticator must be configured with a valid FHIR base URL");
            return;
        }

        String accessToken = buildInternalAccessToken(context, resourceIds);
        String fhirBaseUrl = config.getConfig().get(PatientSelectionFormFactory.INTERNAL_FHIR_URL_PROP_NAME);

        Bundle requestBundle = buildRequestBundle(resourceIds);
        
        try {
            IGenericClient fhirClient = fhirContext.newRestfulGenericClient(fhirBaseUrl);
            fhirClient.registerInterceptor(new BearerTokenAuthInterceptor(accessToken));
            
            Bundle responseBundle = fhirClient.transaction().withBundle(requestBundle).execute();
            
            List<PatientStruct> patients = gatherPatientInfo(responseBundle);
            if (patients.isEmpty()) {
                succeed(context, resourceIds.get(0));
                return;
            }

            if (patients.size() == 1) {
                succeed(context, patients.get(0).getId());
            } else {
                Response response = context.form()
                        .setAttribute("patients", patients)
                        .createForm("patient-select-form.ftl");

                context.challenge(response);
            }
        } catch (BaseServerResponseException e) {
            String msg = "Error while retrieving Patient resources for the selection form";
            LOG.warnf(msg);
            LOG.warnf("Response with status " + e.getStatusCode() + ": " + e.getMessage());
            context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                    Response.status(302)
                    .header("Location", context.getAuthenticationSession().getRedirectUri() +
                            "?error=server_error" +
                            "&error_description=" + msg)
                    .build());
        } catch (Exception e) {
            String msg = "Unexpected error while retrieving Patient resources";
            LOG.error(msg, e);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                    Response.status(302)
                    .header("Location", context.getAuthenticationSession().getRedirectUri() +
                            "?error=server_error" +
                            "&error_description=" + msg)
                    .build());
        }
    }

    private List<String> getResourceIdsForUser(AuthenticationFlowContext context) {
        return context.getUser().getAttributeStream(ATTRIBUTE_RESOURCE_ID)
                .flatMap(a -> Arrays.stream(a.split(" ")))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    private String buildInternalAccessToken(AuthenticationFlowContext context, List<String> resourceIds) {
        KeycloakSession session = context.getSession();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        UserModel user = context.getUser();
        ClientModel client = authSession.getClient();

        UserSessionModel userSession = session.sessions().createUserSession(context.getRealm(), user, user.getUsername(),
                context.getConnection().getRemoteAddr(), null, false, null, null);

        AuthenticatedClientSessionModel authedClientSession = userSession.getAuthenticatedClientSessionByClient(client.getId());
        if (authedClientSession == null) {
            authedClientSession = session.sessions().createClientSession(context.getRealm(), client, userSession);
        }
        authedClientSession.setNote(OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(session.getContext().getUri().getBaseUri(), context.getRealm().getName()));

        // Note: this depends on the corresponding string being registered as a valid scope for this client
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(authedClientSession,
                SMART_SCOPE_PATIENT_READ, session);

        String requestedAudience = authSession.getClientNote(SMART_AUDIENCE_PARAM);
        if (requestedAudience == null) {
            String internalFhirUrl = context.getAuthenticatorConfig().getConfig().get(PatientSelectionFormFactory.INTERNAL_FHIR_URL_PROP_NAME);
            LOG.info("Client request is missing the 'aud' parameter, using '" + internalFhirUrl + "' from config.");
            requestedAudience = internalFhirUrl;
        }

        // Explicit decision not to check the requested audience against the configured internal FHIR URL
        // Checking of the requested audience should be performed in a previous step by the AudienceValidator
        TokenManager tokenManager = new TokenManager();
        AccessToken accessToken = tokenManager.createClientAccessToken(session, context.getRealm(), authSession.getClient(),
                context.getUser(), userSession, clientSessionCtx);

        // Explicitly override the scope string with what we need (less brittle than depending on this to exist as a client scope)
        accessToken.setScope(SMART_SCOPE_PATIENT_READ);

        JsonWebToken jwt = accessToken.audience(requestedAudience);
        jwt.setOtherClaims("patient_id", resourceIds);
        return session.tokens().encode(jwt);
    }

    private Bundle buildRequestBundle(List<String> resourceIds) {
        Bundle bundle = new Bundle();
        bundle.setType(BundleType.BATCH);
        
        for (String id : resourceIds) {
            BundleEntryComponent entry = new BundleEntryComponent();
            BundleEntryRequestComponent request = new BundleEntryRequestComponent();
            request.setMethod(HTTPVerb.GET);
            request.setUrl("Patient/" + id);
            entry.setRequest(request);
            bundle.addEntry(entry);
        }
        
        return bundle;
    }

    private void fail(AuthenticationFlowContext context, String msg) {
        LOG.warn(msg);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                Response.status(302)
                .header("Location", context.getAuthenticationSession().getRedirectUri() +
                        "?error=server_error" +
                        "&error_description=" + msg)
                .build());
    }

    private void succeed(AuthenticationFlowContext context, String patient) {
        // Add selected information to authentication session
        context.getAuthenticationSession().setUserSessionNote("patient_id", patient);
        context.success();
    }

    private List<PatientStruct> gatherPatientInfo(Bundle fhirResponse) {
        List<PatientStruct> patients = new ArrayList<>();

        for (BundleEntryComponent entry : fhirResponse.getEntry()) {
            if (entry.getResponse() == null || entry.getResponse().getStatus() == null ||
                    !entry.getResponse().getStatus().startsWith("200")) {
                continue;
            }

            if (!(entry.getResource() instanceof Patient)) {
                continue;
            }
            
            Patient patient = (Patient) entry.getResource();
            String patientId = patient.getIdElement().getIdPart();

            String patientName = "Missing Name";
            if (patient.getName().isEmpty()) {
                LOG.warn("Patient[id=" + patientId + "] has no name; using placeholder");
            } else {
                if (patient.getName().size() > 1) {
                    LOG.warn("Patient[id=" + patientId + "] has multiple names; using the first one");
                }
                patientName = constructSimpleName(patient.getName().get(0));
            }

            String patientDOB = patient.getBirthDate() == null ? "missing"
                    : patient.getBirthDate().toString();

            patients.add(new PatientStruct(patientId, patientName, patientDOB));
        }

        return patients;
    }

    private String constructSimpleName(HumanName name) {
        if (name.hasText()) {
            return name.getText();
        }

        return Stream.concat(name.getGiven().stream(), Stream.of(name.getFamily()))
                .filter(Objects::nonNull)
                .map(Object::toString)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.joining(" "));
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void action(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String patient = formData.getFirst("patient");

        LOG.debugf("The user selected patient '%s'", patient);

        if (patient == null || patient.trim().isEmpty() || !getResourceIdsForUser(context).contains(patient.trim())) {
            LOG.warnf("The patient selection '%s' is not valid for the authenticated user.", patient.trim());
            context.cancelLogin();

            // reauthenticate...
            authenticate(context);
            return;
        }

        succeed(context, patient.trim());
    }

    @Override
    public void close() {
        // HAPI FHIR client doesn't need explicit cleanup
    }
}
