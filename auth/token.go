package auth

// Tokens is the pair returned to a caller after a successful login or
// token refresh.
type Tokens struct {
	AccessToken  string
	RefreshToken string
}
