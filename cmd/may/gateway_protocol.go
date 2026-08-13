package main

type enrollmentRequest struct {
	DeviceID    string `json:"device_id"`
	DisplayName string `json:"display_name"`
	PublicKey   string `json:"public_key"`
}

type requesterSelfResponse struct {
	DeviceID             string `json:"device_id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Registered           bool   `json:"registered"`
}

type enrollmentCreateResponse struct {
	AlreadyEnrolled      bool   `json:"already_enrolled"`
	DeviceID             string `json:"device_id"`
	DisplayName          string `json:"display_name"`
	EnrollmentID         string `json:"enrollment_id"`
	ExpiresAt            string `json:"expires_at"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Status               string `json:"status"`
}

type enrollmentStatusResponse struct {
	CreatedAt            string `json:"created_at"`
	DeviceID             string `json:"device_id"`
	DisplayName          string `json:"display_name"`
	ExpiresAt            string `json:"expires_at"`
	ID                   string `json:"id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Status               string `json:"status"`
}

type catalogSearchRequest struct {
	Query string `json:"query"`
}

type catalogFieldResult struct {
	FieldID   string `json:"field_id"`
	FieldType string `json:"field_type"`
	Label     string `json:"label"`
}

type catalogItemResult struct {
	Category  string               `json:"category"`
	Fields    []catalogFieldResult `json:"fields"`
	ItemID    string               `json:"item_id"`
	SSH       *catalogSSHMetadata  `json:"ssh,omitempty"`
	Title     string               `json:"title"`
	UpdatedAt string               `json:"updated_at"`
	Version   int64                `json:"version"`
}

type catalogSSHMetadata struct {
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	PublicKey     string `json:"public_key"`
	PublicKeyBlob string `json:"public_key_blob"`
}

type catalogSearchResponse struct {
	Items []catalogItemResult `json:"items"`
}

type clientObservation struct {
	Application string              `json:"application"`
	Identity    applicationIdentity `json:"identity"`
	Source      string              `json:"source"`
}

type applicationAuthorizationScope struct {
	ScopeID   string `json:"scope_id"`
	ScopeKind string `json:"scope_kind"`
}

type createRequest struct {
	Action             string                         `json:"action"`
	AuthorizationScope *applicationAuthorizationScope `json:"authorization_scope,omitempty"`
	Client             clientObservation              `json:"client"`
	ExpectedVersion    int64                          `json:"expected_version"`
	FieldID            string                         `json:"field_id"`
	IdempotencyKey     string                         `json:"idempotency_key"`
	ItemID             string                         `json:"item_id"`
}

type requestStatusResponse struct {
	Error     string `json:"error,omitempty"`
	ExpiresAt string `json:"expires_at"`
	PollToken string `json:"poll_token,omitempty"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

type consumeRequest struct{}

type secretConsumeResponse struct {
	OK        bool    `json:"ok"`
	RequestID string  `json:"request_id"`
	Status    string  `json:"status"`
	Value     *string `json:"value,omitempty"`
}

func (response secretConsumeResponse) secretValue() (string, bool) {
	if response.Value != nil {
		return *response.Value, true
	}
	return "", false
}
