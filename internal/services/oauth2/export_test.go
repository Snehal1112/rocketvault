package oauth2

// SetBurnCompareForTest replaces svc's dummy bcrypt compare, so tests can
// observe which rejections pay for one.
func SetBurnCompareForTest(svc OAuth2Service, burn func(secret string)) {
	svc.(*oauth2Service).burnCompare = burn
}
