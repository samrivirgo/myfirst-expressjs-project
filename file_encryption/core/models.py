from django.db import models 
from django.urls import reverse
from django.contrib.auth.models import User
import uuid



class FileEncryption(models.Model): 
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=200, null=True, blank=True)
    uploade_file = models.FileField(upload_to='images/')
    encrypted_file = models.BinaryField()
    uploaded = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
    shared_with = models.ManyToManyField(User, related_name='shared_files', blank=True)
    share_token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    can_view = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)

    def __str__(self):
        return self.file_name

    def get_absolute_url(self):
        return reverse('download_file', args=[self.id])    