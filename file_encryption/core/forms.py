from django import forms
from .models import FileEncryption
from django.forms import ModelForm
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm

class FileUpload(forms.ModelForm):
    class Meta:
        model = FileEncryption
        fields = ['file_name', 'uploade_file']

        widgets = {
            'file_name': forms.TextInput(attrs={
                'class': 'input input-bordered w-full mb-4',  # DaisyUI input with border and full width
                'placeholder': 'Enter file name'
            }),
            'uploade_file': forms.ClearableFileInput(attrs={
                'class': 'file-input file-input-bordered w-full mb-4',  # DaisyUI file input with border and full width
            }),
        }


User = get_user_model()

class CustomPasswordChangeForm(PasswordChangeForm):
    class Meta:
        model = User
        fields = ('old_password', 'new_password1', 'new_password2')
        widgets = {
            'old_password': forms.PasswordInput(attrs={
                'class': 'input input-bordered w-full', 
                'placeholder': 'Old Password'
            }),
            'new_password1': forms.PasswordInput(attrs={
                'class': 'input input-bordered w-full', 
                'placeholder': 'New Password'
            }),
            'new_password2': forms.PasswordInput(attrs={
                'class': 'input input-bordered w-full', 
                'placeholder': 'Confirm New Password'
            }),
        }