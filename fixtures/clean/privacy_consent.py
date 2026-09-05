# C-047 — clean detector mirror for explicit marketing consent
# The optional control starts off and requires an affirmative action.

class SignupForm(forms.Form):
    marketing_opt_in = forms.BooleanField(initial=False, required=False,
                                          label="Send me product news")
