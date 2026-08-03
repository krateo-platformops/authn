package core

// An object that contains the description of the frontend elements of this login method
type Graphics struct {
	// Icon of the login button
	Icon string `json:"icon"`

	// Text on the login button
	DisplayName string `json:"displayName"`

	// Background color of the login button
	BackgroundColor string `json:"backgroundColor"`

	// Text color of the login button
	TextColor string `json:"textColor"`
}

// An ObjectRef is a reference to an object with a known type in an arbitrary namespace.
type ObjectRef struct {
	// Name of the referenced object.
	Name string `json:"name"`

	// Namespace of the referenced object.
	Namespace string `json:"namespace"`
}

// A SecretKeySelector is a reference to a secret key in an arbitrary namespace.
type SecretKeySelector struct {
	// Name of the referenced object.
	Name string `json:"name"`

	// Namespace of the referenced object.
	Namespace string `json:"namespace"`

	// The key to select.
	Key string `json:"key"`
}

// DeepCopy copy the receiver, creates a new SecretKeySelector.
func (in *SecretKeySelector) DeepCopy() *SecretKeySelector {
	if in == nil {
		return nil
	}
	out := new(SecretKeySelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copy the receiver, writes into out. in must be non-nil.
func (in *SecretKeySelector) DeepCopyInto(out *SecretKeySelector) {
	*out = *in
}
