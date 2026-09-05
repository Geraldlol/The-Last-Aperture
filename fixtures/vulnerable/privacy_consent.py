# V-027 — privacy-and-data-protection / lawful-basis-and-consent-capture / Medium / CWE-359
# Inert detector fixture: the marketing consent control is pre-selected.

class SignupForm(forms.Form):
    marketing_opt_in = forms.BooleanField(initial=True, required=False,
                                          label="Send me product news")
