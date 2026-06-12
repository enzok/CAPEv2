from django import forms
from django_recaptcha.fields import ReCaptchaField
from django_recaptcha.widgets import ReCaptchaV2Checkbox
from allauth.mfa.webauthn.forms import AddWebAuthnForm


class CaptchedSignUpForm(forms.Form):
    captcha = ReCaptchaField(widget=ReCaptchaV2Checkbox)

    def signup(self, request, user):
        pass


class CustomAddWebAuthnForm(AddWebAuthnForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "passwordless" in self.fields:
            self.fields["passwordless"].initial = True
