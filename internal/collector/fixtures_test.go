package collector

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// The kit's tenant. Every response a run needs is canned here, with the URL
// the client sends, query included.
const (
	kitAdminEmail      = "admin@example.com"
	kitCustomerID      = "C123"
	kitOrganizationID  = "123456789"
	kitServiceAccount  = "collector@kit-project.iam.gserviceaccount.com"
	kitTokenURL        = "https://oauth2.googleapis.com/token"
	kitDirectory       = "https://admin.googleapis.com/admin/directory/v1"
	kitReports         = "https://admin.googleapis.com/admin/reports/v1"
	kitGroupSettings   = "https://www.googleapis.com/groups/v1/groups"
	kitCloudIdentity   = "https://cloudidentity.googleapis.com/v1"
	kitAccessContext   = "https://accesscontextmanager.googleapis.com/v1"
	kitVault           = "https://vault.googleapis.com/v1"
	kitTokenResponse   = `{"access_token":"kit-access-token","token_type":"Bearer","expires_in":3600}`
	kitNotYetAvailable = `{"error":{"code":400,"message":"Data for dates later than 2026-04-06 is not yet available. Please check back later","errors":[{"message":"Data for dates later than 2026-04-06 is not yet available. Please check back later","domain":"global","reason":"invalid"}]}}`
	kitForbidden       = `{"error":{"code":403,"message":"Not Authorized to access this resource/api","errors":[{"message":"Not Authorized to access this resource/api","domain":"global","reason":"forbidden"}]}}`
	kitRateLimited     = `{"error":{"code":403,"message":"Rate Limit Exceeded","errors":[{"message":"Rate Limit Exceeded","domain":"usageLimits","reason":"rateLimitExceeded"}]}}`
)

// kitNow is the run's clock: report dates walk back from 2026-04-07 in Pacific
// time.
var kitNow = time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)

// kitKeyJSON is a service account key made once per test binary, so no key
// lives in the repository. Its token_uri is Google's.
var kitKeyJSON = sync.OnceValue(func() string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	raw, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "kit-project",
		"private_key_id": "kit-key",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email":   kitServiceAccount,
		"client_id":      "100000000000000000001",
		"token_uri":      kitTokenURL,
	})
	if err != nil {
		panic(err)
	}
	return string(raw)
})

// Field masks, exactly as the client requests them.
const (
	fieldsUsers           = "kind,nextPageToken,users(id,primaryEmail,suspended,archived,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime,orgUnitPath,creationTime,agreedToTerms,ipWhitelisted,changePasswordAtNextLogin)"
	fieldsRoles           = "kind,nextPageToken,items(roleId,roleName,roleDescription,isSystemRole,isSuperAdminRole,rolePrivileges)"
	fieldsRoleAssignments = "kind,nextPageToken,items(assignedTo,roleId,scopeType,orgUnitId)"
	fieldsGroups          = "kind,nextPageToken,groups(email,name,description,directMembersCount,adminCreated)"
	fieldsMembers         = "kind,nextPageToken,members(email,role,type,status,delivery_settings)"
	fieldsOrgUnits        = "kind,organizationUnits(orgUnitPath,parentOrgUnitPath,name,description,blockInheritance)"
	fieldsMobile          = "kind,nextPageToken,mobiledevices(type,os,model,email,status,lastSync,encryptionStatus,deviceCompromisedStatus,devicePasswordStatus)"
	fieldsChromeOS        = "kind,nextPageToken,chromeosdevices(osVersion,model,annotatedUser,status,lastSync)"
	fieldsDomains         = "kind,domains(domainName,verified,isPrimary)"
	fieldsAccessEvents    = "kind,nextPageToken,items(actor/email,id/time,events(name,parameters(name,value,multiValue,intValue,boolValue)))"
	fieldsActivities      = "kind,nextPageToken,items(actor/email,ipAddress,id/time,id/applicationName,events(name,parameters(name,value,multiValue,intValue,boolValue)))"
	fieldsSAMLProfiles    = "nextPageToken,inboundSamlSsoProfiles(name,displayName,idpConfig(entityId,singleSignOnServiceUri))"
	fieldsSSOAssignments  = "nextPageToken,inboundSsoAssignments(ssoMode,samlSsoInfo(inboundSamlSsoProfile),targetOrgUnit,targetGroup)"
	fieldsAccessPolicies  = "nextPageToken,accessPolicies(name,parent,title)"
	fieldsAccessLevels    = "nextPageToken,accessLevels(name,title,basic(combiningFunction,conditions(negate,ipSubnetworks,regions,requiredAccessLevels,devicePolicy(allowedDeviceManagementLevels,allowedEncryptionStatuses,osConstraints,requireAdminApproval,requireCorpOwned,requireScreenlock))),custom)"
	fieldsVaultMatters    = "nextPageToken,matters(matterId,name,state)"
	fieldsVaultHolds      = "nextPageToken,holds(holdId,name,corpus,updateTime,accounts(accountId),orgUnit(orgUnitId))"
	reportParameterList   = "accounts:num_users,accounts:num_suspended_users,accounts:num_archived_users,accounts:num_7day_logins,accounts:num_30day_logins,accounts:num_users_2sv_enrolled,accounts:num_users_2sv_enforced,accounts:num_users_2sv_protected,accounts:num_users_with_passkeys_enrolled,accounts:num_security_keys,accounts:num_users_password_strength_weak,accounts:num_users_password_length_non_compliant,accounts:num_authorized_apps,accounts:num_locked_users"
)

// apiURL is a Google API URL with the query every generated client sends.
func apiURL(base, path string, query url.Values) string {
	q := url.Values{"alt": {"json"}, "prettyPrint": {"false"}}
	for k, v := range query {
		q[k] = v
	}
	return base + path + "?" + q.Encode()
}

func get(u, body string) collectortest.Response {
	return collectortest.Response{URL: u, Body: body}
}

// kitTenant describes one tenant state. directoryCustomer is what the
// Directory and Policy calls name the customer by, and reportsCustomer what
// the Reports calls send as customerId ("" sends none).
type kitTenant struct {
	directoryCustomer string
	reportsCustomer   string
	customer          collectortest.Response
	reports           []kitReport
	userPages         []string
	roles             string
	roleAssignments   string
	accessEvents      string
	accessPolicies    string
	accessLevels      string
	groups            string
	groupSettings     map[string]string
	groupMembers      map[string]string
	orgUnits          string
	mobileDevices     string
	chromeOSDevices   string
	activities        map[string]map[string]string
	domains           string
	samlProfiles      string
	ssoAssignments    string
	passwordPolicies  string
	sessionPolicies   string
	sessionStatus     int
	lessSecureApps    string
	vaultMatters      string
	vaultHolds        map[string]string
}

type kitReport struct {
	date   string
	status int
	body   string
}

// kitNoSSOAssignments answers the SSO assignments call for a tenant where
// every user signs in with Google.
const kitNoSSOAssignments = `{}`

func cleanTenant() kitTenant {
	return kitTenant{
		directoryCustomer: kitCustomerID,
		reportsCustomer:   kitCustomerID,
		customer:          get(apiURL(kitDirectory, "/customers/my_customer", nil), `{"kind":"admin#directory#customer","id":"C123","customerDomain":"example.com"}`),
		reports: []kitReport{
			{date: "2026-04-07", status: http.StatusBadRequest, body: kitNotYetAvailable},
			{date: "2026-04-06", body: usageReport(map[string]int{
				"accounts:num_users": 8, "accounts:num_suspended_users": 1, "accounts:num_archived_users": 1,
				"accounts:num_7day_logins": 3, "accounts:num_30day_logins": 4,
				"accounts:num_users_2sv_enrolled": 4, "accounts:num_users_2sv_enforced": 2, "accounts:num_users_2sv_protected": 4,
				"accounts:num_users_with_passkeys_enrolled": 1, "accounts:num_security_keys": 2,
				"accounts:num_users_password_strength_weak": 1, "accounts:num_users_password_length_non_compliant": 1,
				"accounts:num_authorized_apps": 5, "accounts:num_locked_users": 0,
			})},
		},
		userPages: []string{
			`{"kind":"admin#directory#users","nextPageToken":"page-2","users":[
				{"id":"u1","primaryEmail":"admin@example.com","isAdmin":true,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"lastLoginTime":"2026-04-08T09:00:00.000Z","orgUnitPath":"/","creationTime":"2024-01-02T03:04:05.000Z","agreedToTerms":true},
				{"id":"u2","primaryEmail":"helpdesk@example.com","isDelegatedAdmin":true,"isEnrolledIn2Sv":true,"lastLoginTime":"2026-04-06T09:00:00.000Z","orgUnitPath":"/Eng","creationTime":"2024-02-02T03:04:05.000Z","agreedToTerms":true},
				{"id":"u3","primaryEmail":"alice@example.com","isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"lastLoginTime":"2026-04-07T09:00:00.000Z","orgUnitPath":"/Eng/Backend","creationTime":"2024-03-02T03:04:05.000Z","agreedToTerms":true,"ipWhitelisted":true},
				{"id":"u4","primaryEmail":"bob@example.com","lastLoginTime":"2025-12-01T09:00:00.000Z","orgUnitPath":"/Sales","creationTime":"2024-04-02T03:04:05.000Z","agreedToTerms":true,"changePasswordAtNextLogin":true},
				{"id":"u5","primaryEmail":"carol@example.com","suspended":true,"isAdmin":true,"lastLoginTime":"2026-01-02T09:00:00.000Z","orgUnitPath":"/Sales","creationTime":"2024-05-02T03:04:05.000Z"}
			]}`,
			`{"kind":"admin#directory#users","users":[
				{"id":"u6","primaryEmail":"dave@example.com","archived":true,"lastLoginTime":"1970-01-01T00:00:00.000Z","orgUnitPath":"/Sales","creationTime":"2024-06-02T03:04:05.000Z"},
				{"id":"u7","primaryEmail":"eve@example.com","isEnrolledIn2Sv":true,"lastLoginTime":"2026-03-25T09:00:00.000Z","orgUnitPath":"/Eng","creationTime":"2024-07-02T03:04:05.000Z","agreedToTerms":true},
				{"id":"u8","primaryEmail":"frank@example.com","lastLoginTime":"1970-01-01T00:00:00.000Z","orgUnitPath":"/Eng","creationTime":"2026-04-01T03:04:05.000Z"}
			]}`,
		},
		roles: `{"kind":"admin#directory#roles","items":[
			{"roleId":"1","roleName":"_SEED_ADMIN_ROLE","roleDescription":"Google Workspace Administrator Seed Role","isSystemRole":true,"isSuperAdminRole":true,"rolePrivileges":[{"privilegeName":"SUPER_ADMIN","serviceId":"01ci93xb3tmzyin"}]},
			{"roleId":"2","roleName":"Helpdesk Lite","roleDescription":"Reset passwords","rolePrivileges":[{"privilegeName":"USERS_RETRIEVE","serviceId":"00haapch16h1ysv"},{"privilegeName":"USERS_UPDATE","serviceId":"00haapch16h1ysv"}]}
		]}`,
		roleAssignments: `{"kind":"admin#directory#roleAssignments","items":[
			{"assignedTo":"u1","roleId":"1","scopeType":"CUSTOMER"},
			{"assignedTo":"u2","roleId":"2","scopeType":"ORG_UNIT","orgUnitId":"03ph8a2z1"}
		]}`,
		accessEvents: `{"kind":"admin#reports#activities","items":[
			{"actor":{"email":"bob@example.com"},"id":{"time":"1775563200"},"events":[{"name":"ACCESS_DENY_EVENT","parameters":[{"name":"CAA_APPLICATION","value":"Gmail"},{"name":"CAA_DEVICE_STATE","value":"Unmanaged"}]}]},
			{"actor":{"email":"eve@example.com"},"id":{"time":"1775476800"},"events":[{"name":"ACCESS_DENY_EVENT","parameters":[{"name":"CAA_APPLICATION","value":"Drive"}]}]}
		]}`,
		accessPolicies: `{"accessPolicies":[{"name":"accessPolicies/111","parent":"organizations/123456789","title":"Corp policy"}]}`,
		accessLevels: `{"accessLevels":[
			{"name":"accessPolicies/111/accessLevels/corp_device","title":"Corp Device","basic":{"conditions":[{"ipSubnetworks":["203.0.113.0/24"],"regions":["US"],"devicePolicy":{"allowedDeviceManagementLevels":["COMPLETE"],"allowedEncryptionStatuses":["ENCRYPTED"],"requireScreenlock":true,"osConstraints":[{"osType":"DESKTOP_MAC"}]}}]}},
			{"name":"accessPolicies/111/accessLevels/custom_expr","title":"Custom Expr","custom":{"expr":{"expression":"true"}}}
		]}`,
		groups: `{"kind":"admin#directory#groups","groups":[
			{"email":"eng@example.com","name":"Eng","description":"Engineering","directMembersCount":"3","adminCreated":true},
			{"email":"social@example.com","name":"Social","directMembersCount":"1","adminCreated":false}
		]}`,
		groupSettings: map[string]string{
			"eng@example.com":    `{"kind":"groupsSettings#groups","email":"eng@example.com","allowExternalMembers":"false","whoCanJoin":"INVITED_CAN_JOIN","whoCanPostMessage":"ALL_MEMBERS_CAN_POST"}`,
			"social@example.com": `{"kind":"groupsSettings#groups","email":"social@example.com","allowExternalMembers":"true","whoCanJoin":"ALL_IN_DOMAIN_CAN_JOIN","whoCanPostMessage":"ANYONE_CAN_POST"}`,
		},
		groupMembers: map[string]string{
			"eng@example.com":    `{"kind":"admin#directory#members","members":[{"email":"admin@example.com","role":"OWNER","type":"USER","status":"ACTIVE"},{"email":"alice@example.com","role":"MEMBER","type":"USER","status":"ACTIVE"},{"email":"eve@example.com","role":"MEMBER","type":"USER","status":"ACTIVE"}]}`,
			"social@example.com": `{"kind":"admin#directory#members","members":[{"email":"partner@vendor.example","role":"MEMBER","type":"USER","status":"ACTIVE","delivery_settings":"ALL_MAIL"}]}`,
		},
		orgUnits: `{"kind":"admin#directory#org_units","organizationUnits":[
			{"orgUnitPath":"/Eng","parentOrgUnitPath":"/","name":"Eng","description":"Engineering"},
			{"orgUnitPath":"/Eng/Backend","parentOrgUnitPath":"/Eng","name":"Backend","blockInheritance":true},
			{"orgUnitPath":"/Sales","parentOrgUnitPath":"/","name":"Sales"}
		]}`,
		mobileDevices: `{"kind":"admin#directory#mobiledevices","mobiledevices":[
			{"type":"ANDROID","os":"Android 14","model":"Pixel 8","email":["alice@example.com"],"status":"APPROVED","lastSync":"2026-04-07T10:00:00.000Z","encryptionStatus":"Encrypted","deviceCompromisedStatus":"No compromise detected","devicePasswordStatus":"On"},
			{"type":"IOS_SYNC","os":"iOS 17.1","model":"iPhone","email":["bob@example.com"],"status":"APPROVED","lastSync":"2026-02-01T10:00:00.000Z","encryptionStatus":"Unencrypted","deviceCompromisedStatus":"Compromise detected","devicePasswordStatus":"Off"}
		]}`,
		chromeOSDevices: `{"kind":"admin#directory#chromeosdevices","chromeosdevices":[
			{"osVersion":"120.0","model":"Chromebook","annotatedUser":"eve@example.com","status":"ACTIVE","lastSync":"2026-04-06T10:00:00.000Z"}
		]}`,
		activities: map[string]map[string]string{
			"drive": {
				"change_user_access":         `{"kind":"admin#reports#activities","items":[{"actor":{"email":"alice@example.com"},"id":{"time":"2026-04-05T10:00:00.000Z","applicationName":"drive"},"events":[{"name":"change_user_access","parameters":[{"name":"target_user","value":"partner@vendor.example"},{"name":"doc_id","value":"doc-1"},{"name":"new_value","multiValue":["can_view"]}]}]}]}`,
				"change_document_visibility": `{"kind":"admin#reports#activities","items":[{"actor":{"email":"eve@example.com"},"id":{"time":"2026-03-20T10:00:00.000Z","applicationName":"drive"},"events":[{"name":"change_document_visibility","parameters":[{"name":"visibility","value":"people_with_link"},{"name":"doc_id","value":"doc-2"}]}]}]}`,
			},
			"admin": {
				"SUSPEND_USER":        `{"kind":"admin#reports#activities","items":[{"actor":{"email":"admin@example.com"},"id":{"time":"2026-04-06T10:00:00.000Z","applicationName":"admin"},"events":[{"name":"SUSPEND_USER","parameters":[{"name":"USER_EMAIL","value":"carol@example.com"}]}]}]}`,
				"CHANGE_SSO_SETTINGS": `{"kind":"admin#reports#activities","items":[{"actor":{"email":"admin@example.com"},"id":{"time":"2026-04-05T10:00:00.000Z","applicationName":"admin"},"events":[{"name":"CHANGE_SSO_SETTINGS"}]}]}`,
			},
			"login": {
				"login_failure":    `{"kind":"admin#reports#activities","items":[{"actor":{"email":"bob@example.com"},"ipAddress":"203.0.113.7","id":{"time":"2026-04-07T10:00:00.000Z","applicationName":"login"},"events":[{"name":"login_failure"}]}]}`,
				"suspicious_login": `{"kind":"admin#reports#activities","items":[{"actor":{"email":"eve@example.com"},"ipAddress":"198.51.100.4","id":{"time":"2026-04-06T10:00:00.000Z","applicationName":"login"},"events":[{"name":"suspicious_login"}]}]}`,
			},
			"token": {
				"authorize": `{"kind":"admin#reports#activities","items":[{"actor":{"email":"alice@example.com"},"id":{"time":"2026-04-04T10:00:00.000Z","applicationName":"token"},"events":[{"name":"authorize","parameters":[{"name":"client_id","value":"111.apps.googleusercontent.com"},{"name":"app_name","value":"Acme Notes"},{"name":"scope","multiValue":["https://www.googleapis.com/auth/drive.readonly","https://www.googleapis.com/auth/userinfo.email"]}]}]}]}`,
			},
		},
		domains:      `{"kind":"admin#directory#domains","domains":[{"domainName":"example.com","verified":true,"isPrimary":true},{"domainName":"example.net","verified":true,"isPrimary":false}]}`,
		samlProfiles: `{"inboundSamlSsoProfiles":[{"name":"inboundSamlSsoProfiles/abc","displayName":"Okta","idpConfig":{"entityId":"https://idp.example.com/entity","singleSignOnServiceUri":"https://idp.example.com/sso/saml?tenant=1"}}]}`,
		// One org unit signs in through the Okta profile.
		ssoAssignments: `{"inboundSsoAssignments":[{"ssoMode":"SAML_SSO","samlSsoInfo":{"inboundSamlSsoProfile":"inboundSamlSsoProfiles/abc"},"targetOrgUnit":"orgUnits/03ph8a2z1"}]}`,
		passwordPolicies: `{"policies":[
			{"name":"policies/aaa","customer":"customers/C123","type":"ADMIN","policyQuery":{"orgUnit":"orgUnits/03ph8a2z1"},"setting":{"type":"settings/security.password","value":{"minimumLength":12,"maximumLength":100,"allowedStrength":"STRONG","enforceRequirementsAtLogin":true,"allowReuse":false,"expirationDuration":"7776000s"}}},
			{"name":"policies/bbb","customer":"customers/C123","type":"ADMIN","setting":{"type":"settings/security.password","value":{"minimumLength":8,"maximumLength":64,"allowedStrength":"WEAK","allowReuse":true}}}
		]}`,
		// The tenant keeps the 14-day default web session and shortens it
		// to 12 hours for one org unit, which also allows less secure apps.
		sessionPolicies: `{"policies":[
			{"name":"policies/ccc","customer":"customers/C123","type":"SYSTEM","policyQuery":{"orgUnit":"orgUnits/root"},"setting":{"type":"settings/security.session_controls","value":{"webSessionDuration":"1209600s"}}},
			{"name":"policies/ddd","customer":"customers/C123","type":"ADMIN","policyQuery":{"orgUnit":"orgUnits/03ph8a2z1"},"setting":{"type":"settings/security.session_controls","value":{"webSessionDuration":"43200s"}}}
		]}`,
		lessSecureApps: `{"policies":[
			{"name":"policies/eee","customer":"customers/C123","type":"SYSTEM","policyQuery":{"orgUnit":"orgUnits/root"},"setting":{"type":"settings/security.less_secure_apps","value":{}}},
			{"name":"policies/fff","customer":"customers/C123","type":"ADMIN","policyQuery":{"orgUnit":"orgUnits/03ph8a2z1"},"setting":{"type":"settings/security.less_secure_apps","value":{"allowLessSecureApps":true}}}
		]}`,
		vaultMatters: `{"matters":[{"matterId":"m1","name":"Litigation hold","state":"OPEN"}]}`,
		vaultHolds: map[string]string{
			"m1": `{"holds":[{"holdId":"h1","name":"Mail hold","corpus":"MAIL","updateTime":"2026-03-01T00:00:00Z","accounts":[{"accountId":"u3"}]},{"holdId":"h2","name":"Drive hold","corpus":"DRIVE","orgUnit":{"orgUnitId":"03ph8a2z1"}}]}`,
		},
	}
}

// emptyTenant is a new tenant: its usage report is not out yet, and the only
// thing in it is the admin the collector signs in as.
func emptyTenant() kitTenant {
	t := cleanTenant()
	t.reports = nil
	for day := 1; day <= maxReportRetries; day++ {
		date := reportDateFor(kitNow, day)
		t.reports = append(t.reports, kitReport{date: date, body: `{"kind":"admin#reports#usageReports","warnings":[{"code":"DATA_NOT_AVAILABLE","message":"Data is not available for date ` + date + ` for application accounts."}]}`})
	}
	t.userPages = []string{`{"kind":"admin#directory#users","users":[
		{"id":"u1","primaryEmail":"admin@example.com","isAdmin":true,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"lastLoginTime":"2026-04-08T09:00:00.000Z","orgUnitPath":"/","creationTime":"2026-04-01T03:04:05.000Z","agreedToTerms":true}
	]}`}
	t.roles = `{"kind":"admin#directory#roles","items":[{"roleId":"1","roleName":"_SEED_ADMIN_ROLE","isSystemRole":true,"isSuperAdminRole":true}]}`
	t.roleAssignments = `{"kind":"admin#directory#roleAssignments","items":[{"assignedTo":"u1","roleId":"1","scopeType":"CUSTOMER"}]}`
	t.accessEvents = `{"kind":"admin#reports#activities"}`
	t.accessPolicies = `{}`
	t.groups = `{"kind":"admin#directory#groups"}`
	t.orgUnits = `{"kind":"admin#directory#org_units"}`
	t.mobileDevices = `{"kind":"admin#directory#mobiledevices"}`
	t.chromeOSDevices = `{"kind":"admin#directory#chromeosdevices"}`
	t.activities = nil
	t.domains = `{"kind":"admin#directory#domains","domains":[{"domainName":"example.com","verified":true,"isPrimary":true}]}`
	t.samlProfiles = `{}`
	t.passwordPolicies = `{}`
	t.sessionPolicies = `{}`
	t.lessSecureApps = `{}`
	t.vaultMatters = `{}`
	return t
}

// reportLagTenant replays the 2SV enrollment incident: the usage report, two
// days behind, counts six of seven users enrolled, while the Directory shows
// the seventh enrolled since.
// readOnlyAdminTenant is the clean tenant with the delegated admin's role
// able only to retrieve users.
func readOnlyAdminTenant() kitTenant {
	t := cleanTenant()
	t.roles = strings.Replace(t.roles, `{"privilegeName":"USERS_UPDATE","serviceId":"00haapch16h1ysv"}`, `{"privilegeName":"ORGANIZATION_UNITS_RETRIEVE","serviceId":"00haapch16h1ysv"}`, 1)
	return t
}

func reportLagTenant() kitTenant {
	t := cleanTenant()
	t.ssoAssignments = kitNoSSOAssignments
	t.reports = []kitReport{{date: "2026-04-07", body: usageReport(map[string]int{
		"accounts:num_users": 7, "accounts:num_suspended_users": 0, "accounts:num_archived_users": 0,
		"accounts:num_7day_logins": 6, "accounts:num_30day_logins": 7,
		"accounts:num_users_2sv_enrolled": 6, "accounts:num_users_2sv_enforced": 6, "accounts:num_users_2sv_protected": 6,
		"accounts:num_users_with_passkeys_enrolled": 0, "accounts:num_security_keys": 0,
		"accounts:num_users_password_strength_weak": 0, "accounts:num_users_password_length_non_compliant": 0,
		"accounts:num_authorized_apps": 2, "accounts:num_locked_users": 0,
	})}}
	users := `{"kind":"admin#directory#users","users":[
		{"id":"u1","primaryEmail":"admin@example.com","isAdmin":true,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"lastLoginTime":"2026-04-08T09:00:00.000Z","orgUnitPath":"/"}`
	for i := 2; i <= 7; i++ {
		users += fmt.Sprintf(`,{"id":"u%d","primaryEmail":"user%d@example.com","isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"lastLoginTime":"2026-04-07T09:00:00.000Z","orgUnitPath":"/Eng"}`, i, i)
	}
	t.userPages = []string{users + `]}`}
	return t
}

// delegatedAdminTenant replays the delegated admin incident: the collector
// signs in as an admin without Super Admin, which Google refuses the tenant
// record. Every other call goes out under the customer key.
func delegatedAdminTenant() kitTenant {
	t := cleanTenant()
	t.directoryCustomer = "my_customer"
	t.reportsCustomer = ""
	t.customer = collectortest.Response{URL: t.customer.URL, Status: http.StatusForbidden, Body: kitForbidden}
	t.passwordPolicies = `{"policies":[{"name":"policies/aaa","setting":{"type":"settings/security.password","value":{"minimumLength":12,"maximumLength":100,"allowedStrength":"STRONG","enforceRequirementsAtLogin":true}}}]}`
	return t
}

// kitScopeInsufficient is Google's answer to a token without the scope a
// call needs.
const kitScopeInsufficient = `{"error":{"code":403,"message":"Request had insufficient authentication scopes.","errors":[{"message":"Insufficient Permission","domain":"global","reason":"insufficientPermissions"}],"status":"PERMISSION_DENIED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"ACCESS_TOKEN_SCOPE_INSUFFICIENT","domain":"googleapis.com"}]}}`

// sessionScopeDeniedTenant is the clean tenant with the session controls
// read refused, as Google refuses a token without its scope.
func sessionScopeDeniedTenant() kitTenant {
	t := cleanTenant()
	t.sessionStatus = http.StatusForbidden
	t.sessionPolicies = kitScopeInsufficient
	return t
}

// sessionWithoutLengthTenant is the clean tenant with a session controls
// policy that sets no session length.
func sessionWithoutLengthTenant() kitTenant {
	t := cleanTenant()
	t.sessionPolicies = `{"policies":[{"name":"policies/ccc","setting":{"type":"settings/security.session_controls","value":{}}}]}`
	return t
}

// lessSecureAppsBlockedTenant is the clean tenant with less secure apps
// blocked for every org unit.
func lessSecureAppsBlockedTenant() kitTenant {
	t := cleanTenant()
	t.lessSecureApps = `{"policies":[{"name":"policies/eee","type":"SYSTEM","setting":{"type":"settings/security.less_secure_apps","value":{}}}]}`
	return t
}

// partialReportTenant has a partial usage report for the newest date, with 0
// passkey users and 0 security keys. The complete report for the day before
// has both.
func partialReportTenant() kitTenant {
	t := cleanTenant()
	t.ssoAssignments = kitNoSSOAssignments
	t.reports[0] = kitReport{date: "2026-04-07", body: partialUsageReport("2026-04-07", map[string]int{
		"accounts:num_users": 8, "accounts:num_suspended_users": 1, "accounts:num_archived_users": 1,
		"accounts:num_users_2sv_protected": 4, "accounts:num_users_with_passkeys_enrolled": 0,
		"accounts:num_security_keys": 0, "accounts:num_authorized_apps": 5,
	})}
	return t
}

// allPartialReportsTenant has a partial usage report for every date the
// collector tries.
func allPartialReportsTenant() kitTenant {
	t := cleanTenant()
	t.reports = nil
	for day := 1; day <= maxReportRetries; day++ {
		date := reportDateFor(kitNow, day)
		t.reports = append(t.reports, kitReport{date: date, body: partialUsageReport(date, map[string]int{"accounts:num_users": 8})})
	}
	return t
}

// partialUsageReport is a usage report with the values and the partial-data
// warning the Reports API reference gives for date.
func partialUsageReport(date string, values map[string]int) string {
	warning := `{"code":"PARTIAL_DATA_AVAILABLE","message":"Data for date ` + date + ` for application \"accounts\" is not available right now, please try again after a few hours."}`
	return strings.Replace(usageReport(values), `{"kind":"admin#reports#usageReports",`, `{"kind":"admin#reports#usageReports","warnings":[`+warning+`],`, 1)
}

func usageReport(values map[string]int) string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	params := make([]map[string]string, 0, len(names))
	for _, name := range names {
		params = append(params, map[string]string{"name": name, "intValue": fmt.Sprint(values[name])})
	}
	raw, _ := json.Marshal(map[string]any{
		"kind":         "admin#reports#usageReports",
		"usageReports": []any{map[string]any{"kind": "admin#reports#usageReport", "date": "2026-04-06", "parameters": params}},
	})
	return string(raw)
}

// responses lists the canned responses for the tenant at the internal level,
// which makes every call the lower levels make and more.
func (t kitTenant) responses() []collectortest.Response {
	dc := t.directoryCustomer
	reportsQuery := func(q url.Values) url.Values {
		if t.reportsCustomer != "" {
			q.Set("customerId", t.reportsCustomer)
		}
		return q
	}
	out := []collectortest.Response{
		{Method: http.MethodPost, URL: kitTokenURL, Body: kitTokenResponse},
		t.customer,
	}
	for _, r := range t.reports {
		out = append(out, collectortest.Response{
			URL:    apiURL(kitReports, "/usage/dates/"+r.date, reportsQuery(url.Values{"parameters": {reportParameterList}})),
			Status: r.status,
			Body:   r.body,
		})
	}
	for i, page := range t.userPages {
		q := url.Values{"customer": {"my_customer"}, "maxResults": {"500"}, "projection": {"full"}, "viewType": {"admin_view"}, "fields": {fieldsUsers}}
		if i > 0 {
			q.Set("pageToken", fmt.Sprintf("page-%d", i+1))
		}
		out = append(out, get(apiURL(kitDirectory, "/users", q), page))
	}
	out = append(out,
		get(apiURL(kitDirectory, "/customer/"+dc+"/roles", url.Values{"maxResults": {"100"}, "fields": {fieldsRoles}}), t.roles),
		get(apiURL(kitDirectory, "/customer/"+dc+"/roleassignments", url.Values{"maxResults": {"200"}, "fields": {fieldsRoleAssignments}}), t.roleAssignments),
		get(apiURL(kitReports, "/activity/users/all/applications/context_aware_access", reportsQuery(url.Values{
			"eventName": {"ACCESS_DENY_EVENT"}, "startTime": {kitNow.AddDate(0, 0, -DefaultContextAwareAccessLookbackDays).Format(time.RFC3339)},
			"maxResults": {"1000"}, "fields": {fieldsAccessEvents},
		})), t.accessEvents),
		get(apiURL(kitAccessContext, "/accessPolicies", url.Values{"parent": {"organizations/" + kitOrganizationID}, "pageSize": {"100"}, "fields": {fieldsAccessPolicies}}), t.accessPolicies),
		get(apiURL(kitAccessContext, "/accessPolicies/111/accessLevels", url.Values{"pageSize": {"100"}, "fields": {fieldsAccessLevels}}), t.accessLevels),
		get(apiURL(kitDirectory, "/groups", url.Values{"customer": {dc}, "maxResults": {"200"}, "fields": {fieldsGroups}}), t.groups),
		get(apiURL(kitDirectory, "/customer/"+dc+"/orgunits", url.Values{"type": {"all"}, "fields": {fieldsOrgUnits}}), t.orgUnits),
		get(apiURL(kitDirectory, "/customer/"+dc+"/devices/mobile", url.Values{"maxResults": {"100"}, "projection": {"BASIC"}, "fields": {fieldsMobile}}), t.mobileDevices),
		get(apiURL(kitDirectory, "/customer/"+dc+"/devices/chromeos", url.Values{"maxResults": {"100"}, "projection": {"BASIC"}, "fields": {fieldsChromeOS}}), t.chromeOSDevices),
		get(apiURL(kitDirectory, "/customer/"+dc+"/domains", url.Values{"fields": {fieldsDomains}}), t.domains),
		get(apiURL(kitCloudIdentity, "/inboundSamlSsoProfiles", url.Values{"pageSize": {"100"}, "fields": {fieldsSAMLProfiles}}), t.samlProfiles),
		get(apiURL(kitCloudIdentity, "/inboundSsoAssignments", url.Values{"pageSize": {"100"}, "fields": {fieldsSSOAssignments}}), t.ssoAssignments),
		get(apiURL(kitCloudIdentity, "/policies", url.Values{
			"filter":   {`setting.type.matches('^settings/security.password$') && customer == "customers/` + dc + `"`},
			"pageSize": {"100"},
		}), t.passwordPolicies),
		collectortest.Response{URL: apiURL(kitCloudIdentity, "/policies", url.Values{
			"filter":   {`setting.type.matches('^settings/security.session_controls$') && customer == "customers/` + dc + `"`},
			"pageSize": {"100"},
		}), Status: t.sessionStatus, Body: t.sessionPolicies},
		get(apiURL(kitCloudIdentity, "/policies", url.Values{
			"filter":   {`setting.type.matches('^settings/security.less_secure_apps$') && customer == "customers/` + dc + `"`},
			"pageSize": {"100"},
		}), t.lessSecureApps),
		get(apiURL(kitVault, "/matters", url.Values{"pageSize": {"100"}, "view": {"BASIC"}, "fields": {fieldsVaultMatters}}), t.vaultMatters),
	)
	for email, body := range t.groupSettings {
		out = append(out, get(apiURL(kitGroupSettings, "/"+email, nil), body))
	}
	for email, body := range t.groupMembers {
		out = append(out, get(apiURL(kitDirectory, "/groups/"+email+"/members", url.Values{"maxResults": {"200"}, "fields": {fieldsMembers}}), body))
	}
	for matter, body := range t.vaultHolds {
		out = append(out, get(apiURL(kitVault, "/matters/"+matter+"/holds", url.Values{"pageSize": {"100"}, "fields": {fieldsVaultHolds}}), body))
	}
	out = append(out, t.activityResponses(reportsQuery)...)
	return out
}

// withCustomerKey adds the responses the tenant gives when the collector
// cannot read the tenant record and names the customer by its key, as it does
// under a fault on the customer read.
func (t kitTenant) withCustomerKey() []collectortest.Response {
	out := t.responses()
	seen := map[string]bool{}
	for _, r := range out {
		seen[r.Method+" "+r.URL] = true
	}
	fallback := t
	fallback.directoryCustomer = "my_customer"
	fallback.reportsCustomer = ""
	for _, r := range fallback.responses() {
		if !seen[r.Method+" "+r.URL] {
			out = append(out, r)
		}
	}
	return out
}

// activityResponses answers each audit-log request, one per event name, with
// the tenant's events or none.
func (t kitTenant) activityResponses(reportsQuery func(url.Values) url.Values) []collectortest.Response {
	week := kitNow.AddDate(0, 0, -AuditLogWindowDays).Format(time.RFC3339)
	month := kitNow.AddDate(0, 0, -DriveExternalSharingCountDays).Format(time.RFC3339)
	adminEvents := make([]string, 0, len(securityRelevantAdminEvents))
	for name := range securityRelevantAdminEvents {
		adminEvents = append(adminEvents, name)
	}
	apps := []struct {
		name   string
		since  string
		events []string
	}{
		{"drive", month, driveExternalSharingEvents},
		{"admin", week, adminEvents},
		{"login", week, securityRelevantLoginEvents},
		{"token", week, []string{tokenEventAuthorize}},
	}
	var out []collectortest.Response
	for _, app := range apps {
		for _, event := range app.events {
			body, ok := t.activities[app.name][event]
			if !ok {
				body = `{"kind":"admin#reports#activities"}`
			}
			out = append(out, get(apiURL(kitReports, "/activity/users/all/applications/"+app.name, reportsQuery(url.Values{
				"eventName": {event}, "startTime": {app.since}, "maxResults": {"1000"}, "fields": {fieldsActivities},
			})), body))
		}
	}
	return out
}
