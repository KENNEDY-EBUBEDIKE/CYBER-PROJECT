from django.shortcuts import render, redirect
from django.apps import apps
from django.contrib.auth.decorators import login_required
from binascii import hexlify
from apps.features.models import Vault, SharedSecret, LockKey
from utilities.cryptography import generate_shared_secret, encrypt_file

user_model = apps.get_model("users", "User")


@login_required()
def upload_file(request):
    if request.method == "POST":
        no_of_secrets = int(request.POST.get('no_of_secrets'))
        unlock_secrets = int(request.POST.get('unlock_secrets'))
        secret_holders = request.POST.getlist('secret_holders')
        document_name = request.POST.get('document_name')
        document = request.FILES.get('document')

        if (no_of_secrets >= unlock_secrets) and (no_of_secrets == len(secret_holders)):

            # SAVE FILE
            new_document = Vault.objects.add_document(
                user=request.user,
                document_name=document_name,
                document_file=document,
                req_unlock=unlock_secrets,
                status="Encrypted With shared Secret"
            )
            new_document.save()

            # GET KEY AND SECRETS
            shares, key = generate_shared_secret(unlock_secrets, no_of_secrets)

            # ENCRYPT THE FILE
            enc_file = encrypt_file(new_document, key)
            print(enc_file)

            # SHARE THE SECRETS
            for i in range(len(shares)):
                new_secret = SharedSecret.objects.assign_secret(
                    name=document_name,
                    owner=user_model.objects.get(id=secret_holders[i]),
                    file=new_document,
                    index=shares[i][0],
                    secret=hexlify(shares[i][1]).decode('utf-8')
                )
                new_secret.save()

            # SAVE THE KEY
            new_key = LockKey()
            new_key.key = hexlify(key).decode('utf-8')
            new_key.file = new_document
            new_key.save()
        else:
            print("Invalid Config")
            return redirect('upload_file')
        return redirect('vault')
    all_users = user_model.objects.all()
    return render(request, 'upload-documents.html', {'all_users': all_users})


@login_required()
def vault(request):
    vault_items = Vault.objects.all()
    return render(request, 'vault.html', {'vault_items': vault_items})


@login_required()
def user_shared_secrets(request):
    secrets = request.user.shared_secrets.all()
    return render(request, 'shared_secrets.html', {'secrets': secrets})
