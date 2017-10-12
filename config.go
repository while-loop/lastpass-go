package lastpass

// ConfigFunc allows modification of configurations
// in the Vault struct
type ConfigFunc func(opts *ConfigOptions)

// ConfigOptions are config options that
// set behaviours in Vault.
// Current supported configs is 2FA.
type ConfigOptions struct {
	twoFa int
}

// With2Factor adds two factor auth to your
// vault.
func With2Factor(pin int) ConfigFunc {
	return func(opts *ConfigOptions) {
		opts.twoFa = pin
	}
}
