from django.db import models
import os
from django.db import IntegrityError


class SharedSecretManager(models.Manager):
    def assign_secret(self, name, owner, file, secret, index):

        new_secret = self.model(
            name=name,
            owner=owner,
            file=file,
            secret=secret,
            secret_index=index
        )
        new_secret.save(using=self._db)

        return new_secret


class SharedSecret(models.Model):
    name = models.CharField(max_length=255, null=False, blank=False)
    owner = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='shared_secrets')
    file = models.ForeignKey('Vault', on_delete=models.CASCADE, related_name='shared_secrets', null=True)
    secret = models.CharField(max_length=255, null=True, blank=False)
    secret_index = models.IntegerField(blank=False, null=False, default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = SharedSecretManager()

    def __str__(self):
        return self.name


class VaultManager(models.Manager):

    def add_document(self, user, document_name, document_file, req_unlock, status):
        if not user:
            raise ValueError('USER IS REQUIRED!!')
        if not document_name:
            raise ValueError('Name IS REQUIRED!!')
        new_document = self.model(
            uploaded_by=user,
            document=document_file,
            req_unlock=req_unlock,
            status=status
        )

        new_document.document.name = f'{document_name}.{document_file.name.split(".")[-1]}'
        new_document.name = f'{document_name}'
        new_document.save(using=self._db)
        return new_document


class Vault(models.Model):
    name = models.CharField(max_length=255, unique=True, null=False, blank=False, default="File")
    uploaded_by = models.ForeignKey('users.User', on_delete=models.CASCADE, related_name='vault_documents')
    document = models.FileField(upload_to='file/', null=False)
    status = models.CharField(max_length=255, null=False, blank=False, default="Encrypted With shared Secret")
    req_unlock = models.IntegerField(blank=False, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = VaultManager()

    def delete_file(self):
        # os.remove(os.path.join(settings.MEDIA_ROOT, self.document.name))
        self.delete()
        os.remove(self.document.path)
        return "SUCCESS"

    def __str__(self):
        return self.name


class LockKey(models.Model):
    key = models.CharField(max_length=255, null=False, blank=False)
    file = models.OneToOneField('Vault', on_delete=models.CASCADE, unique=True, related_name='lock_key')

    def __str__(self):
        return self.file
