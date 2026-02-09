package provider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"dario.cat/mergo"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/keycloak/terraform-provider-keycloak/internal/keycloak/adminv2/admin"
	"github.com/keycloak/terraform-provider-keycloak/internal/keycloak/adminv2/models"
	"github.com/keycloak/terraform-provider-keycloak/keycloak"
	"github.com/keycloak/terraform-provider-keycloak/keycloak/types"
	abstractions "github.com/microsoft/kiota-abstractions-go"
)

var (
	keycloakOpenidClientAccessTypes                          = []string{"CONFIDENTIAL", "PUBLIC", "BEARER-ONLY"}
	keycloakOpenidClientAuthorizationPolicyEnforcementMode   = []string{"ENFORCING", "PERMISSIVE", "DISABLED"}
	keycloakOpenidClientResourcePermissionDecisionStrategies = []string{"UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"}
	keycloakOpenidClientPkceCodeChallengeMethod              = []string{"", "plain", "S256"}
)

// ====================================================================================
// ADMIN-V2 API INTEGRATION
// ====================================================================================

func supportsAdminV2(ctx context.Context, kc *keycloak.KeycloakClient) bool {
	version, err := kc.Version(ctx)
	if err != nil {
		return false
	}
	versionStr := version.String()
	if strings.Contains(versionStr, "SNAPSHOT") {
		return true
	}
	minVersion := keycloak.Version("27.0.0").AsVersion()
	return version.GreaterThanOrEqual(minVersion)
}

func canUseAdminV2ForClient(client *keycloak.OpenidClient) (bool, string) {
	if client.AuthorizationServicesEnabled {
		return false, "authorization_services"
	}
	if client.AuthenticationFlowBindingOverrides.BrowserId != "" || client.AuthenticationFlowBindingOverrides.DirectGrantId != "" {
		return false, "auth_flow_overrides"
	}
	if len(client.Attributes.ExtraConfig) > 0 {
		return false, "extra_config"
	}
	if client.ConsentRequired {
		return false, "consent_required"
	}
	// For CONFIDENTIAL clients (not public, not bearer-only), we need an explicit secret
	// The legacy API auto-generates secrets, but admin-v2 doesn't support this
	if !client.PublicClient && !client.BearerOnly && client.ClientSecret == "" {
		return false, "confidential_without_secret"
	}
	// For CONFIDENTIAL clients, we need at least one login flow explicitly enabled
	// The legacy API uses defaults, but admin-v2 requires explicit flows
	if !client.PublicClient && !client.BearerOnly {
		hasAnyFlow := client.StandardFlowEnabled || client.ImplicitFlowEnabled ||
			client.DirectAccessGrantsEnabled || client.ServiceAccountsEnabled
		if !hasAnyFlow {
			return false, "confidential_without_flows"
		}
	}
	return true, ""
}

func convertToAdminV2OIDCClient(client *keycloak.OpenidClient) *models.OIDCClientRepresentation {
	v2 := models.NewOIDCClientRepresentation()

	// Base fields
	protocol := "openid-connect"
	v2.SetProtocol(&protocol)
	v2.SetClientId(&client.ClientId)
	v2.SetEnabled(&client.Enabled)

	if client.Name != "" {
		v2.SetDisplayName(&client.Name)
	}
	if client.Description != "" {
		v2.SetDescription(&client.Description)
	}
	if client.BaseUrl != "" {
		v2.SetAppUrl(&client.BaseUrl)
	}
	if len(client.ValidRedirectUris) > 0 {
		v2.SetRedirectUris(client.ValidRedirectUris)
	}
	if len(client.WebOrigins) > 0 {
		v2.SetWebOrigins(client.WebOrigins)
	}

	// Login flows
	flows := []models.Flow{}
	if client.StandardFlowEnabled {
		flow := models.STANDARD_FLOW
		flows = append(flows, flow)
	}
	if client.ImplicitFlowEnabled {
		flow := models.IMPLICIT_FLOW
		flows = append(flows, flow)
	}
	if client.DirectAccessGrantsEnabled {
		flow := models.DIRECT_GRANT_FLOW
		flows = append(flows, flow)
	}
	if client.ServiceAccountsEnabled {
		flow := models.SERVICE_ACCOUNT_FLOW
		flows = append(flows, flow)
	}
	if len(flows) > 0 {
		v2.SetLoginFlows(flows)
	}

	// Auth (for confidential clients)
	// Only set auth if we have a secret to provide
	// If no secret is provided, don't send auth object and let Keycloak auto-generate the secret
	if client.ClientSecret != "" {
		auth := models.NewAuth()
		method := "secret"
		auth.SetMethod(&method)
		auth.SetSecret(&client.ClientSecret)
		v2.SetAuth(auth)
	}

	return v2
}

func createClientV2(ctx context.Context, kc *keycloak.KeycloakClient, client *keycloak.OpenidClient) error {
	v2Client := convertToAdminV2OIDCClient(client)

	// Log what we're about to send
	tflog.Debug(ctx, "Creating client with admin-v2 via Kiota", map[string]interface{}{
		"clientId":     *v2Client.GetClientId(),
		"protocol":     *v2Client.GetProtocol(),
		"enabled":      *v2Client.GetEnabled(),
		"hasAuth":      v2Client.GetAuth() != nil,
		"loginFlows":   v2Client.GetLoginFlows(),
		"redirectUris": v2Client.GetRedirectUris(),
		"webOrigins":   v2Client.GetWebOrigins(),
		"realmId":      client.RealmId,
	})
	if v2Client.GetAuth() != nil {
		auth := v2Client.GetAuth()
		tflog.Debug(ctx, "Auth details", map[string]interface{}{
			"method":    auth.GetMethod(),
			"hasSecret": auth.GetSecret() != nil && *auth.GetSecret() != "",
		})
	}

	// Wrap in the POST request body type
	body := admin.NewWithVersionPostRequestBody()
	body.SetOIDCClientRepresentation(v2Client)

	// Use Kiota client to POST
	adminV2 := kc.GetAdminV2Client()
	requestConfig := &abstractions.RequestConfiguration[abstractions.DefaultQueryParameters]{}

	_, err := adminV2.Admin().Api().ByRealmName(client.RealmId).Clients().ByVersion("v2").Post(ctx, body, requestConfig)
	if err != nil {
		tflog.Error(ctx, "Admin-v2 POST failed", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("admin-v2 POST failed: %w", err)
	}

	// Admin-v2 API doesn't return ID in Location header or response body
	// Use legacy API to get the ID by clientId
	var clients []keycloak.GenericClient
	err = kc.Get(ctx, fmt.Sprintf("/realms/%s/clients", client.RealmId), &clients, map[string]string{
		"clientId": client.ClientId,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch created client ID: %w", err)
	}

	if len(clients) == 0 {
		return fmt.Errorf("client was created but not found when searching by clientId")
	}

	client.Id = clients[0].Id

	tflog.Debug(ctx, "Retrieved client ID from legacy API", map[string]interface{}{
		"id":       client.Id,
		"clientId": client.ClientId,
	})

	return nil
}

func getClientV2(ctx context.Context, kc *keycloak.KeycloakClient, realmId, id string) (*keycloak.OpenidClient, error) {
	var v2 map[string]interface{}
	err := kc.Get(ctx, fmt.Sprintf("/api/%s/clients/v2/%s", realmId, id), &v2, nil)
	if err != nil {
		return nil, err
	}

	// Convert from admin-v2 format to OpenidClient
	client := &keycloak.OpenidClient{
		Id:       id,
		RealmId:  realmId,
		Protocol: "openid-connect",
	}

	if clientId, ok := v2["clientId"].(string); ok {
		client.ClientId = clientId
	}
	if name, ok := v2["displayName"].(string); ok {
		client.Name = name
	}
	if desc, ok := v2["description"].(string); ok {
		client.Description = desc
	}
	if enabled, ok := v2["enabled"].(bool); ok {
		client.Enabled = enabled
	}
	if appUrl, ok := v2["appUrl"].(string); ok {
		client.BaseUrl = appUrl
	}
	if redirects, ok := v2["redirectUris"].([]interface{}); ok {
		uris := make([]string, 0, len(redirects))
		for _, r := range redirects {
			if s, ok := r.(string); ok {
				uris = append(uris, s)
			}
		}
		client.ValidRedirectUris = uris
	}
	if origins, ok := v2["webOrigins"].([]interface{}); ok {
		uris := make([]string, 0, len(origins))
		for _, r := range origins {
			if s, ok := r.(string); ok {
				uris = append(uris, s)
			}
		}
		client.WebOrigins = uris
	}

	// Parse login flows
	if flows, ok := v2["loginFlows"].([]interface{}); ok {
		for _, flow := range flows {
			if flowStr, ok := flow.(string); ok {
				switch flowStr {
				case "STANDARD":
					client.StandardFlowEnabled = true
				case "IMPLICIT":
					client.ImplicitFlowEnabled = true
				case "DIRECT_GRANT":
					client.DirectAccessGrantsEnabled = true
				case "SERVICE_ACCOUNT":
					client.ServiceAccountsEnabled = true
				}
			}
		}
	}

	// Parse auth - get client secret
	if auth, ok := v2["auth"].(map[string]interface{}); ok {
		if secret, ok := auth["secret"].(string); ok {
			client.ClientSecret = secret
		}
		// Admin-v2 always uses "secret" method for confidential clients
		client.ClientAuthenticatorType = "client-secret"
	}

	client.PublicClient = client.ClientSecret == ""

	return client, nil
}

func updateClientV2(ctx context.Context, kc *keycloak.KeycloakClient, client *keycloak.OpenidClient) error {
	v2Client := convertToAdminV2OIDCClient(client)

	tflog.Debug(ctx, "Updating client with admin-v2 via Kiota", map[string]interface{}{
		"clientId":   *v2Client.GetClientId(),
		"id":         client.Id,
		"hasAuth":    v2Client.GetAuth() != nil,
		"loginFlows": v2Client.GetLoginFlows(),
		"realmId":    client.RealmId,
	})

	// Wrap in the PUT request body type
	body := admin.NewWithVersionPostRequestBody()
	body.SetOIDCClientRepresentation(v2Client)

	// Use Kiota client to PUT
	adminV2 := kc.GetAdminV2Client()
	requestConfig := &abstractions.RequestConfiguration[abstractions.DefaultQueryParameters]{}

	_, err := adminV2.Admin().Api().ByRealmName(client.RealmId).Clients().ByVersion("v2").ById(client.Id).Put(ctx, body, requestConfig)
	if err != nil {
		tflog.Error(ctx, "Admin-v2 PUT failed", map[string]interface{}{
			"error": err.Error(),
		})
	}
	return err
}

func deleteClientV2(ctx context.Context, kc *keycloak.KeycloakClient, realmId, id string) error {
	adminV2 := kc.GetAdminV2Client()
	requestConfig := &abstractions.RequestConfiguration[abstractions.DefaultQueryParameters]{}

	return adminV2.Admin().Api().ByRealmName(realmId).Clients().ByVersion("v2").ById(id).Delete(ctx, requestConfig)
}

// ====================================================================================
// END ADMIN-V2 INTEGRATION
// ====================================================================================

func resourceKeycloakOpenidClient() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceKeycloakOpenidClientCreate,
		ReadContext:   resourceKeycloakOpenidClientRead,
		DeleteContext: resourceKeycloakOpenidClientDelete,
		UpdateContext: resourceKeycloakOpenidClientUpdate,
		// This resource can be imported using {{realm}}/{{client_id}}. The Client ID is displayed in the GUI
		Importer: &schema.ResourceImporter{
			StateContext: resourceKeycloakOpenidClientImport,
		},
		Schema: map[string]*schema.Schema{
			"client_id": {
				Type:     schema.TypeString,
				Required: true,
			},
			"realm_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"description": {
				Type:             schema.TypeString,
				Optional:         true,
				DiffSuppressFunc: suppressDiffWhenNotInConfig("description"),
			},
			"access_type": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice(keycloakOpenidClientAccessTypes, false),
			},
			"client_secret": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				Sensitive:     true,
				ConflictsWith: []string{"client_secret_wo", "client_secret_wo_version", "client_secret_regenerate_when_changed"},
			},
			"client_secret_wo": {
				Type:          schema.TypeString,
				Optional:      true,
				Sensitive:     true,
				WriteOnly:     true,
				ConflictsWith: []string{"client_secret", "client_secret_regenerate_when_changed"},
				RequiredWith:  []string{"client_secret_wo_version"},
				Description:   "Client Secret as write-only argument",
			},
			"client_secret_wo_version": {
				Type:          schema.TypeInt,
				Optional:      true,
				ConflictsWith: []string{"client_secret", "client_secret_regenerate_when_changed"},
				RequiredWith:  []string{"client_secret_wo"},
				Description:   "Version of the Client secret write-only argument",
			},
			"client_secret_regenerate_when_changed": {
				Type:          schema.TypeMap,
				Description:   "Arbitrary map of values that, when changed, will trigger rotation of the secret",
				Optional:      true,
				ConflictsWith: []string{"client_secret", "client_secret_wo", "client_secret_wo_version"},
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"client_authenticator_type": {
				Type:     schema.TypeString,
				Optional: true,
				// No validation is performed since Keycloak plugins can register custom client authenticators
				Default: "client-secret",
			},
			"standard_flow_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"implicit_flow_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"direct_access_grants_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"service_accounts_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"frontchannel_logout_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"valid_redirect_uris": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
				Optional: true,
				Computed: true,
			},
			"valid_post_logout_redirect_uris": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
				Optional: true,
				Computed: true,
			},
			"web_origins": {
				Type:     schema.TypeSet,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
				Optional: true,
				Computed: true,
			},
			"root_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"admin_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"base_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"service_account_user_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"pkce_code_challenge_method": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice(keycloakOpenidClientPkceCodeChallengeMethod, false),
			},
			"require_dpop_bound_tokens": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"access_token_lifespan": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"client_offline_session_idle_timeout": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"client_offline_session_max_lifespan": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"client_session_idle_timeout": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"client_session_max_lifespan": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"exclude_session_state_from_auth_response": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"exclude_issuer_from_auth_response": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"resource_server_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"authorization": {
				Type:     schema.TypeSet,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"policy_enforcement_mode": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringInSlice(keycloakOpenidClientAuthorizationPolicyEnforcementMode, false),
						},
						"decision_strategy": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validation.StringInSlice(keycloakOpenidClientResourcePermissionDecisionStrategies, false),
							Default:      "UNANIMOUS",
						},
						"allow_remote_resource_management": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"keep_defaults": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
			},
			"full_scope_allowed": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"consent_required": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"display_on_consent_screen": {
				Type:     schema.TypeBool,
				Optional: true,
				Computed: true,
			},
			"consent_screen_text": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"authentication_flow_binding_overrides": {
				Type:     schema.TypeSet,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"browser_id": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"direct_grant_id": {
							Type:     schema.TypeString,
							Optional: true,
						},
					},
				},
			},
			"login_theme": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"use_refresh_tokens": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"use_refresh_tokens_client_credentials": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"standard_token_exchange_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"allow_refresh_token_in_standard_token_exchange": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"frontchannel_logout_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"backchannel_logout_url": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"backchannel_logout_session_required": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"backchannel_logout_revoke_offline_sessions": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"extra_config": {
				Type:             schema.TypeMap,
				Optional:         true,
				ValidateDiagFunc: validateExtraConfig(reflect.ValueOf(&keycloak.OpenidClientAttributes{}).Elem()),
			},
			"oauth2_device_authorization_grant_enabled": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"oauth2_device_code_lifespan": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"oauth2_device_polling_interval": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"always_display_in_console": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"import": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
				ForceNew: true,
			},
		},
		CustomizeDiff: resourceKeycloakOpenidClientDiff(),
	}
}

func resourceKeycloakOpenidClientDiff() schema.CustomizeDiffFunc {
	return customdiff.All(
		customdiff.ComputedIf("service_account_user_id", func(ctx context.Context, d *schema.ResourceDiff, meta interface{}) bool {
			return d.HasChange("service_accounts_enabled")
		}),
		customdiff.ComputedIf("client_secret", func(ctx context.Context, d *schema.ResourceDiff, meta interface{}) bool {
			return d.HasChange("client_secret_regenerate_when_changed")
		}),
	)
}

func getOpenidClientFromData(data *schema.ResourceData) (*keycloak.OpenidClient, error) {
	validRedirectUris := make([]string, 0)
	webOrigins := make([]string, 0)
	validPostLogoutRedirectUris := make([]string, 0)

	rootUrlData, rootUrlOk := data.GetOkExists("root_url")
	validRedirectUrisData, validRedirectUrisOk := data.GetOk("valid_redirect_uris")
	webOriginsData, webOriginsOk := data.GetOk("web_origins")
	validPostLogoutRedirectUrisData, validPostLogoutRedirectUrisOk := data.GetOk("valid_post_logout_redirect_uris")
	description, descriptionOk := data.GetOkExists("description")

	rootUrlString := rootUrlData.(string)

	if validRedirectUrisOk {
		for _, validRedirectUri := range validRedirectUrisData.(*schema.Set).List() {
			validRedirectUris = append(validRedirectUris, validRedirectUri.(string))
		}
	}

	if webOriginsOk {
		for _, webOrigin := range webOriginsData.(*schema.Set).List() {
			webOrigins = append(webOrigins, webOrigin.(string))
		}
	}

	if validPostLogoutRedirectUrisOk {
		for _, validPostLogoutRedirectUri := range validPostLogoutRedirectUrisData.(*schema.Set).List() {
			validPostLogoutRedirectUris = append(validPostLogoutRedirectUris, validPostLogoutRedirectUri.(string))
		}
	}

	openidClient := &keycloak.OpenidClient{
		Id:                        data.Id(),
		ClientId:                  data.Get("client_id").(string),
		RealmId:                   data.Get("realm_id").(string),
		Name:                      data.Get("name").(string),
		Enabled:                   data.Get("enabled").(bool),
		ClientSecret:              data.Get("client_secret").(string),
		ClientAuthenticatorType:   data.Get("client_authenticator_type").(string),
		StandardFlowEnabled:       data.Get("standard_flow_enabled").(bool),
		ImplicitFlowEnabled:       data.Get("implicit_flow_enabled").(bool),
		DirectAccessGrantsEnabled: data.Get("direct_access_grants_enabled").(bool),
		ServiceAccountsEnabled:    data.Get("service_accounts_enabled").(bool),
		FrontChannelLogoutEnabled: data.Get("frontchannel_logout_enabled").(bool),
		FullScopeAllowed:          data.Get("full_scope_allowed").(bool),
		Attributes: keycloak.OpenidClientAttributes{
			PkceCodeChallengeMethod:                  data.Get("pkce_code_challenge_method").(string),
			RequireDPoPBoundTokens:                   types.KeycloakBoolQuoted(data.Get("require_dpop_bound_tokens").(bool)),
			ExcludeSessionStateFromAuthResponse:      types.KeycloakBoolQuoted(data.Get("exclude_session_state_from_auth_response").(bool)),
			ExcludeIssuerFromAuthResponse:            types.KeycloakBoolQuoted(data.Get("exclude_issuer_from_auth_response").(bool)),
			AccessTokenLifespan:                      data.Get("access_token_lifespan").(string),
			LoginTheme:                               data.Get("login_theme").(string),
			ClientOfflineSessionIdleTimeout:          data.Get("client_offline_session_idle_timeout").(string),
			ClientOfflineSessionMaxLifespan:          data.Get("client_offline_session_max_lifespan").(string),
			ClientSessionIdleTimeout:                 data.Get("client_session_idle_timeout").(string),
			ClientSessionMaxLifespan:                 data.Get("client_session_max_lifespan").(string),
			UseRefreshTokens:                         types.KeycloakBoolQuoted(data.Get("use_refresh_tokens").(bool)),
			UseRefreshTokensClientCredentials:        types.KeycloakBoolQuoted(data.Get("use_refresh_tokens_client_credentials").(bool)),
			StandardTokenExchangeEnabled:             types.KeycloakBoolQuoted(data.Get("standard_token_exchange_enabled").(bool)),
			AllowRefreshTokenInStandardTokenExchange: data.Get("allow_refresh_token_in_standard_token_exchange").(string),
			FrontchannelLogoutUrl:                    data.Get("frontchannel_logout_url").(string),
			BackchannelLogoutUrl:                     data.Get("backchannel_logout_url").(string),
			BackchannelLogoutRevokeOfflineTokens:     types.KeycloakBoolQuoted(data.Get("backchannel_logout_revoke_offline_sessions").(bool)),
			BackchannelLogoutSessionRequired:         types.KeycloakBoolQuoted(data.Get("backchannel_logout_session_required").(bool)),
			ExtraConfig:                              getExtraConfigFromData(data),
			Oauth2DeviceAuthorizationGrantEnabled:    types.KeycloakBoolQuoted(data.Get("oauth2_device_authorization_grant_enabled").(bool)),
			Oauth2DeviceCodeLifespan:                 data.Get("oauth2_device_code_lifespan").(string),
			Oauth2DevicePollingInterval:              data.Get("oauth2_device_polling_interval").(string),
			ConsentScreenText:                        data.Get("consent_screen_text").(string),
			DisplayOnConsentScreen:                   types.KeycloakBoolQuoted(data.Get("display_on_consent_screen").(bool)),
			PostLogoutRedirectUris:                   types.KeycloakSliceHashDelimited(validPostLogoutRedirectUris),
		},
		ValidRedirectUris:      validRedirectUris,
		WebOrigins:             webOrigins,
		AdminUrl:               data.Get("admin_url").(string),
		BaseUrl:                data.Get("base_url").(string),
		ConsentRequired:        data.Get("consent_required").(bool),
		AlwaysDisplayInConsole: data.Get("always_display_in_console").(bool),
	}

	// Handle write-only secret
	// During CREATE (data.Id() == ""), use the secret if version is set
	// During UPDATE, use the secret only if version changed
	woVersion := data.Get("client_secret_wo_version").(int)
	if woVersion != 0 {
		isCreate := data.Id() == ""
		hasChange := data.HasChange("client_secret_wo_version")
		if isCreate || hasChange {
			clientSecretWriteOnly, clientSecretWriteOnlyDiags := data.GetRawConfigAt(cty.GetAttrPath("client_secret_wo"))
			if clientSecretWriteOnlyDiags.HasError() {
				return nil, errors.New("error reading 'client_secret_wo' argument")
			}

			openidClient.ClientSecret = clientSecretWriteOnly.AsString()
		}
	}

	if rootUrlOk {
		openidClient.RootUrl = &rootUrlString
	}

	if !openidClient.ImplicitFlowEnabled && !openidClient.StandardFlowEnabled {
		if _, ok := data.GetOk("valid_redirect_uris"); ok {
			return nil, errors.New("valid_redirect_uris cannot be set when standard or implicit flow is not enabled")
		}
	}

	if !openidClient.ImplicitFlowEnabled && !openidClient.StandardFlowEnabled && !openidClient.DirectAccessGrantsEnabled {
		if _, ok := data.GetOk("web_origins"); ok {
			return nil, errors.New("web_origins cannot be set when standard or implicit flow is not enabled")
		}
	}

	// access type
	if accessType := data.Get("access_type").(string); accessType == "PUBLIC" {
		openidClient.PublicClient = true
	} else if accessType == "BEARER-ONLY" {
		openidClient.BearerOnly = true
	}

	if v, ok := data.GetOk("authorization"); ok {
		openidClient.AuthorizationServicesEnabled = true
		authorizationSettingsData := v.(*schema.Set).List()[0]
		authorizationSettings := authorizationSettingsData.(map[string]interface{})
		openidClient.AuthorizationSettings = &keycloak.OpenidClientAuthorizationSettings{
			PolicyEnforcementMode:         authorizationSettings["policy_enforcement_mode"].(string),
			DecisionStrategy:              authorizationSettings["decision_strategy"].(string),
			AllowRemoteResourceManagement: authorizationSettings["allow_remote_resource_management"].(bool),
			KeepDefaults:                  authorizationSettings["keep_defaults"].(bool),
		}
	} else {
		openidClient.AuthorizationServicesEnabled = false
	}

	if v, ok := data.GetOk("authentication_flow_binding_overrides"); ok {
		authenticationFlowBindingOverridesData := v.(*schema.Set).List()[0]
		authenticationFlowBindingOverrides := authenticationFlowBindingOverridesData.(map[string]interface{})
		openidClient.AuthenticationFlowBindingOverrides = keycloak.OpenidAuthenticationFlowBindingOverrides{
			BrowserId:     authenticationFlowBindingOverrides["browser_id"].(string),
			DirectGrantId: authenticationFlowBindingOverrides["direct_grant_id"].(string),
		}
	}

	// description, preserve empty string for update
	if descriptionOk {
		openidClient.Description = description.(string) // will be "" if user set empty string
	}

	return openidClient, nil
}

func setOpenidClientData(ctx context.Context, keycloakClient *keycloak.KeycloakClient, data *schema.ResourceData, client *keycloak.OpenidClient) error {
	var serviceAccountUserId string
	if client.ServiceAccountsEnabled {
		serviceAccountUser, err := keycloakClient.GetOpenidClientServiceAccountUserId(ctx, client.RealmId, client.Id)
		if err != nil {
			return err
		}
		serviceAccountUserId = serviceAccountUser.Id
	}
	data.SetId(client.Id)
	data.Set("client_id", client.ClientId)
	data.Set("realm_id", client.RealmId)
	data.Set("name", client.Name)
	data.Set("enabled", client.Enabled)
	data.Set("description", client.Description)

	// Normalize client_authenticator_type only for clients that could use admin-v2
	// Admin-v2 API returns "secret" but schema default is "client-secret"
	// Only normalize if client doesn't use features that require legacy API
	authenticatorType := client.ClientAuthenticatorType
	if supportsAdminV2(ctx, keycloakClient) && (authenticatorType == "" || authenticatorType == "secret") {
		// Only normalize if client doesn't have features that prevent admin-v2 usage
		// (ignore extra_config check as legacy API adds default values that admin-v2 created clients also have)
		shouldNormalize := !client.AuthorizationServicesEnabled &&
			!client.ConsentRequired &&
			client.AuthenticationFlowBindingOverrides.BrowserId == "" &&
			client.AuthenticationFlowBindingOverrides.DirectGrantId == ""

		if shouldNormalize {
			authenticatorType = "client-secret"
		}
	}
	data.Set("client_authenticator_type", authenticatorType)
	data.Set("standard_flow_enabled", client.StandardFlowEnabled)
	data.Set("implicit_flow_enabled", client.ImplicitFlowEnabled)
	data.Set("direct_access_grants_enabled", client.DirectAccessGrantsEnabled)
	data.Set("service_accounts_enabled", client.ServiceAccountsEnabled)
	data.Set("frontchannel_logout_enabled", client.FrontChannelLogoutEnabled)
	data.Set("valid_redirect_uris", client.ValidRedirectUris)
	data.Set("valid_post_logout_redirect_uris", client.Attributes.PostLogoutRedirectUris)
	data.Set("web_origins", client.WebOrigins)
	data.Set("admin_url", client.AdminUrl)
	data.Set("base_url", client.BaseUrl)
	data.Set("root_url", &client.RootUrl)
	data.Set("full_scope_allowed", client.FullScopeAllowed)
	data.Set("consent_required", client.ConsentRequired)
	data.Set("always_display_in_console", client.AlwaysDisplayInConsole)

	data.Set("pkce_code_challenge_method", client.Attributes.PkceCodeChallengeMethod)
	data.Set("require_dpop_bound_tokens", client.Attributes.RequireDPoPBoundTokens)
	data.Set("access_token_lifespan", client.Attributes.AccessTokenLifespan)
	data.Set("login_theme", client.Attributes.LoginTheme)
	// Admin-v2 API doesn't return use.refresh.tokens, so it defaults to false
	// But the schema default is true, so use true when API returns false to avoid drift
	// If a user explicitly wants false, they should set it in config and terraform will apply the change
	useRefreshTokens := bool(client.Attributes.UseRefreshTokens)
	if !useRefreshTokens {
		useRefreshTokens = true // Use schema default
	}
	data.Set("use_refresh_tokens", useRefreshTokens)
	data.Set("use_refresh_tokens_client_credentials", client.Attributes.UseRefreshTokensClientCredentials)
	data.Set("standard_token_exchange_enabled", client.Attributes.StandardTokenExchangeEnabled)
	data.Set("allow_refresh_token_in_standard_token_exchange", client.Attributes.AllowRefreshTokenInStandardTokenExchange)
	data.Set("oauth2_device_authorization_grant_enabled", client.Attributes.Oauth2DeviceAuthorizationGrantEnabled)
	data.Set("oauth2_device_code_lifespan", client.Attributes.Oauth2DeviceCodeLifespan)
	data.Set("oauth2_device_polling_interval", client.Attributes.Oauth2DevicePollingInterval)
	data.Set("client_offline_session_idle_timeout", client.Attributes.ClientOfflineSessionIdleTimeout)
	data.Set("client_offline_session_max_lifespan", client.Attributes.ClientOfflineSessionMaxLifespan)
	data.Set("client_session_idle_timeout", client.Attributes.ClientSessionIdleTimeout)
	data.Set("client_session_max_lifespan", client.Attributes.ClientSessionMaxLifespan)
	data.Set("display_on_consent_screen", client.Attributes.DisplayOnConsentScreen)
	data.Set("consent_screen_text", client.Attributes.ConsentScreenText)
	data.Set("frontchannel_logout_url", client.Attributes.FrontchannelLogoutUrl)
	data.Set("backchannel_logout_url", client.Attributes.BackchannelLogoutUrl)
	data.Set("backchannel_logout_revoke_offline_sessions", client.Attributes.BackchannelLogoutRevokeOfflineTokens)
	data.Set("backchannel_logout_session_required", client.Attributes.BackchannelLogoutSessionRequired)
	setExtraConfigData(data, client.Attributes.ExtraConfig)

	if client.AuthorizationServicesEnabled {
		data.Set("resource_server_id", client.Id)

		if client.AuthorizationSettings != nil {
			authorizationSettings := make(map[string]interface{})
			authorizationSettings["policy_enforcement_mode"] = client.AuthorizationSettings.PolicyEnforcementMode
			authorizationSettings["decision_strategy"] = client.AuthorizationSettings.DecisionStrategy
			authorizationSettings["allow_remote_resource_management"] = client.AuthorizationSettings.AllowRemoteResourceManagement
			// keep_defaults is not returned by API (json:"-"), preserve config value or default to false
			keepDefaults := false
			if v, ok := data.GetOk("authorization"); ok {
				existingAuth := v.(*schema.Set).List()
				if len(existingAuth) > 0 {
					keepDefaults = existingAuth[0].(map[string]interface{})["keep_defaults"].(bool)
				}
			}
			authorizationSettings["keep_defaults"] = keepDefaults
			data.Set("authorization", []interface{}{authorizationSettings})
		}
	}

	if client.ServiceAccountsEnabled {
		data.Set("service_account_user_id", serviceAccountUserId)
	} else {
		data.Set("service_account_user_id", "")
	}

	if v, ok := data.GetOk("client_secret_wo_version"); ok && v != nil {
		data.Set("client_secret_wo_version", v.(int))
	} else {
		data.Set("client_secret", client.ClientSecret)
	}

	// access typess
	if client.PublicClient {
		data.Set("access_type", "PUBLIC")
	} else if client.BearerOnly {
		data.Set("access_type", "BEARER-ONLY")
	} else {
		data.Set("access_type", "CONFIDENTIAL")
	}

	if (keycloak.OpenidAuthenticationFlowBindingOverrides{}) == client.AuthenticationFlowBindingOverrides {
		data.Set("authentication_flow_binding_overrides", nil)
	} else {
		authenticationFlowBindingOverridesSettings := make(map[string]interface{})
		authenticationFlowBindingOverridesSettings["browser_id"] = client.AuthenticationFlowBindingOverrides.BrowserId
		authenticationFlowBindingOverridesSettings["direct_grant_id"] = client.AuthenticationFlowBindingOverrides.DirectGrantId
		data.Set("authentication_flow_binding_overrides", []interface{}{authenticationFlowBindingOverridesSettings})
	}

	return nil
}

func resourceKeycloakOpenidClientCreate(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	client, err := getOpenidClientFromData(data)
	if err != nil {
		return diag.FromErr(err)
	}

	err = keycloakClient.ValidateOpenidClient(ctx, client)
	if err != nil {
		return diag.FromErr(err)
	}

	if data.Get("import").(bool) {
		existingClient, err := keycloakClient.GetOpenidClientByClientId(ctx, client.RealmId, client.ClientId)
		if err != nil {
			return diag.FromErr(err)
		}

		if err = mergo.Merge(client, existingClient); err != nil {
			return diag.FromErr(err)
		}

		err = keycloakClient.UpdateOpenidClient(ctx, client)
		if err != nil {
			return diag.FromErr(err)
		}
	} else {
		useV2, reason := canUseAdminV2ForClient(client)
		if supportsAdminV2(ctx, keycloakClient) && useV2 {
			tflog.Info(ctx, "Using admin-v2 API for client creation", map[string]interface{}{"clientId": client.ClientId})
			err = createClientV2(ctx, keycloakClient, client)
		} else {
			if reason != "" {
				tflog.Info(ctx, "Using legacy API for client creation", map[string]interface{}{"reason": reason})
			}
			err = keycloakClient.NewOpenidClient(ctx, client)
		}
		if err != nil {
			return diag.FromErr(err)
		}
	}

	data.SetId(client.Id)

	return resourceKeycloakOpenidClientRead(ctx, data, meta)
}

func resourceKeycloakOpenidClientRead(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	id := data.Id()

	// TODO: Enable admin-v2 reads when Keycloak fixes the GET endpoint
	// For now, admin-v2 GET returns 404 for clients created via admin-v2 POST
	client, err := keycloakClient.GetOpenidClient(ctx, realmId, id)
	if err != nil {
		return handleNotFoundError(ctx, err, data)
	}

	err = setOpenidClientData(ctx, keycloakClient, data, client)
	if err != nil {
		return diag.FromErr(err)
	}

	if _, ok := data.GetOk("import"); !ok {
		data.Set("import", false)
	}

	return nil
}

func resourceKeycloakOpenidClientUpdate(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	client, err := getOpenidClientFromData(data)
	if err != nil {
		return diag.FromErr(err)
	}

	err = keycloakClient.ValidateOpenidClient(ctx, client)
	if err != nil {
		return diag.FromErr(err)
	}

	err = evaluateSecretRegeneration(ctx, keycloakClient, data, client)
	if err != nil {
		return diag.FromErr(err)
	}

	// For updates, always use legacy API to avoid compatibility issues
	// TODO: Use admin-v2 for updates once we can properly handle all client attributes
	tflog.Info(ctx, "Using legacy API for client update")
	err = keycloakClient.UpdateOpenidClient(ctx, client)
	if err != nil {
		return diag.FromErr(err)
	}

	err = setOpenidClientData(ctx, keycloakClient, data, client)
	if err != nil {
		return diag.FromErr(err)
	}

	return nil
}

func resourceKeycloakOpenidClientDelete(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if data.Get("import").(bool) {
		return nil
	}
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	id := data.Id()

	var err error
	if supportsAdminV2(ctx, keycloakClient) {
		tflog.Info(ctx, "Using admin-v2 API for client deletion", map[string]interface{}{"id": id})
		err = deleteClientV2(ctx, keycloakClient, realmId, id)
		// Admin-v2 DELETE has the same bug as GET - returns 404 for clients created via admin-v2
		// Fall back to legacy API if admin-v2 fails
		if err != nil {
			tflog.Debug(ctx, "Admin-v2 delete failed, falling back to legacy", map[string]interface{}{"error": err.Error()})
			err = keycloakClient.DeleteOpenidClient(ctx, realmId, id)
		}
	} else {
		err = keycloakClient.DeleteOpenidClient(ctx, realmId, id)
	}
	return diag.FromErr(err)
}

func resourceKeycloakOpenidClientImport(ctx context.Context, d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	parts := strings.Split(d.Id(), "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("Invalid import. Supported import formats: {{realmId}}/{{openidClientId}}")
	}

	_, err := keycloakClient.GetOpenidClient(ctx, parts[0], parts[1])
	if err != nil {
		return nil, err
	}

	d.Set("realm_id", parts[0])
	d.Set("import", false)
	d.SetId(parts[1])

	diagnostics := resourceKeycloakOpenidClientRead(ctx, d, meta)
	if diagnostics.HasError() {
		return nil, errors.New(diagnostics[0].Summary)
	}

	return []*schema.ResourceData{d}, nil
}

func evaluateSecretRegeneration(ctx context.Context, keycloakClient *keycloak.KeycloakClient, d *schema.ResourceData, client *keycloak.OpenidClient) error {

	if d.HasChange("client_secret_regenerate_when_changed") {
		secret, err := keycloakClient.RegenerateOpenIdClientSecret(ctx, client)
		if err != nil {
			return err
		}

		client.ClientSecret = secret.Value
		d.Set("client_secret", secret.Value)
	}

	return nil
}
