from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from django.contrib.auth.decorators import login_required
from apps.features.models import Vault, RSAKeyPair
import time
from binascii import hexlify, unhexlify
from django.db import IntegrityError
from utilities.cryptography import generate_shared_secret,\
    encrypt_file, retrieve_shared_key, decrypt_file, generate_rsa_key_pair


@api_view(["POST"])
@login_required()
def download(request):
    doc = Vault.objects.get(id=request.data.get("id"))

    return Response(
        data={
            "success": True,
            "file": doc.document.url
        },
        status=status.HTTP_200_OK,

    )


@api_view(["POST"])
@login_required()
def decrypt(request):
    secs = request.data["secrets"]
    indices = request.data["indices"]

    if len(secs) == len(indices):
        shares = [(indices[i], unhexlify(secs[i])) for i in range(len(secs))]

        key = retrieve_shared_key(shares)
        try:
            doc = Vault.objects.get(lock_key__key=hexlify(key).decode('utf-8'))
            if doc.status != "Decrypted and Open":
                file = decrypt_file(doc,  key)
                doc.status = "Decrypted and Open"
                doc.save()
            else:
                file = doc
        except ObjectDoesNotExist:
            return Response(
                data={
                    "success": False,
                    "message": "Invalid Secret"
                },
                status=status.HTTP_200_OK,

            )
    else:
        return Response(
            data={
                "success": False,
                "message": "Indices And Secret MisMatch!",
            },
            status=status.HTTP_200_OK,

        )
    return Response(
        data={
            "success": True,
            "message": "Successful!",
            "file": file.document.url
        },
        status=status.HTTP_200_OK,

    )


@api_view(["POST"])
@login_required()
def done(request):
    time.sleep(20)
    doc = Vault.objects.get(id=request.data.get("id"))

    if doc.status == "Decrypted and Open":

        doc.status = "Encrypted With shared Secret"
        doc.save()

        no_of_unlock_secrets = doc.req_unlock
        no_of_secrets = len(doc.shared_secrets.all())

        # GET KEY AND SECRETS
        shares, key = generate_shared_secret(no_of_unlock_secrets, no_of_secrets)

        # ENC
        enc_file = encrypt_file(doc, key)
        print(enc_file)

        # SHARE THE SECRETS
        for i, sec in enumerate(doc.shared_secrets.all()):
            sec.index = shares[i][0],
            sec.secret = hexlify(shares[i][1]).decode('utf-8')
            sec.save()

        # SAVE THE KEY
        lock_key = doc.lock_key
        lock_key.key = hexlify(key).decode('utf-8')
        lock_key.save()

    return Response(
        data={
            "success": True,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["DELETE"])
@login_required()
def delete_file(request):
    doc = Vault.objects.get(id=request.data.get("id"))
    doc.delete_file()
    return Response(
        data={
            "success": True,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@login_required()
def generate_key_pair(request):
    if request.method == "POST":
        size = int(request.data.get('size'))
        private_key, public_key = generate_rsa_key_pair(size)

        new_pair = RSAKeyPair.objects.generate(
            name=request.user.username,
            owner=request.user,
            public_key=public_key,
            private_key=private_key,
        )
        try:
            new_pair.save()
        except IntegrityError:
            return Response(
                data={
                    "success": False,
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            data={
                "success": True,
            },
            status=status.HTTP_200_OK,
        )
