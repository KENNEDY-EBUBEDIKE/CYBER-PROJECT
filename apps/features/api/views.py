from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from django.contrib.auth.decorators import login_required
from apps.features.models import Vault, RSAKeyPair, Signatures
import time
from django.contrib.auth import get_user_model
from binascii import hexlify, unhexlify
from django.db import IntegrityError
from utilities.cryptography import generate_shared_secret,\
    encrypt_file,\
    retrieve_shared_key,\
    decrypt_file,\
    generate_rsa_key_pair,\
    digital_signature, verify_digital_signature
User = get_user_model()


@api_view(["POST"])
@login_required()
def download(request):
    time.sleep(2)
    doc = Vault.objects.get(id=int(request.data.get("id")))

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
    time.sleep(1)
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
        except Vault.DoesNotExist:
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
    time.sleep(1)
    doc = Vault.objects.get(id=request.data.get("id"))
    doc.delete_file()
    return Response(
        data={
            "success": True,
            "message": "File Deleted"
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@login_required()
def generate_key_pair(request):
    if request.method == "POST":
        try:
            if bool(request.user.key_pair):
                return Response(
                    data={
                        "success": False,
                        'error': "Key Pair Exist For this account!"
                    },
                    status=status.HTTP_200_OK,
                )
        except User.key_pair.RelatedObjectDoesNotExist:

            size = int(request.data.get('size'))
            private_key, public_key = generate_rsa_key_pair(size)
            try:
                new_pair = RSAKeyPair.objects.generate(
                    name=request.user.username,
                    owner=request.user,
                    public_key=public_key,
                    private_key=private_key,
                )

                new_pair.save()
            except IntegrityError:
                return Response(
                    data={
                        "success": False,
                        'error': "Key Pair Exist For this account!"
                    },
                    status=status.HTTP_200_OK,
                )

            return Response(
                data={
                    "success": True,
                    'message': "Key Pair Generated Successfully"
                },
                status=status.HTTP_200_OK,
            )


@api_view(["POST"])
@login_required()
def delete_key_pair(request):
    time.sleep(1)
    try:
        pair = request.user.key_pair
        pair.delete_key_pair()
        return Response(
            data={
                "success": True,
                'message': "Public and Private Key Pair Successfully Deleted",
            },
            status=status.HTTP_200_OK,

        )
    except User.key_pair.RelatedObjectDoesNotExist:
        return Response(
            data={
                "success": False,
                'error': "You have no key Pair! Please Generate"
            },
            status=status.HTTP_200_OK,

        )


@api_view(["POST"])
@login_required()
def download_private_key(request):
    time.sleep(1)
    try:
        key_pair = request.user.key_pair
        return Response(
            data={
                "success": True,
                "pri_key": key_pair.private_key.url,
                'message': "Successful"
            },
            status=status.HTTP_200_OK,

        )
    except User.key_pair.RelatedObjectDoesNotExist:
        return Response(
                data={
                    "success": False,
                    'error': "You have no key Pair! Please Generate"
                },
                status=status.HTTP_200_OK,

            )


@api_view(["POST"])
@login_required()
def sign_document(request):
    doc = Vault.objects.get(id=request.data['id'])
    try:
        private_key = request.user.key_pair.private_key
    except User.key_pair.RelatedObjectDoesNotExist:
        return Response(
            data={
                "success": False,
                'message': "You have no key Pair! Please Generate"
            },
            status=status.HTTP_200_OK,
        )
    signature = digital_signature(doc.document.path, private_key.path)
    try:
        new_signature = Signatures.objects.create_signature(

            document=doc,
            signer=request.user,
            signature=signature,
        )
        new_signature.save()
    except ValueError as e:
        return Response(
            data={
                "success": False,
                'message': e
            },
            status=status.HTTP_200_OK,
        )

    return Response(
        data={
            "success": True,
            'message': "Document Signed Successfully"
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@login_required()
def verify_document_signature(request):
    doc = Vault.objects.get(id=request.data['id'])
    try:
        signature = doc.signature.signature
    except Vault.signature.RelatedObjectDoesNotExist:
        return Response(
            data={
                "success": False,
                'message': "This Document is not Signed"
            },
            status=status.HTTP_200_OK,
        )
    try:
        public_key = doc.signature.signer.key_pair.public_key
    except User.key_pair.RelatedObjectDoesNotExist:
        return Response(
            data={
                "success": False,
                'message': "This Document Cant be verified!\n The Signer has no Key"
            },
            status=status.HTTP_200_OK,
        )
    try:
        verified = verify_digital_signature(doc.document.path, public_key.path, signature.path)
        if verified:
            return Response(
                data={
                    "success": True,
                    'message': "Document is Authentic, Verified! and Signed",
                    "signer": f'{doc.signature.signer.surname} {doc.signature.signer.first_name}'
                },
                status=status.HTTP_200_OK,
            )
    except ValueError as e:

        return Response(
            data={
                "success": False,
                'message': f"Document has {e} !!!"
            },
            status=status.HTTP_200_OK,
        )


@api_view(["DELETE"])
@login_required()
def unsign_document(request):
    signature = Signatures.objects.get(id=request.data['id'])
    signature.delete_signature()
    return Response(
        data={
            "success": True,
            'message': "Document Unsigned!"
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@login_required()
def download_signature(request):
    time.sleep(1)
    signature = Signatures.objects.get(id=int(request.data.get("id")))

    return Response(
        data={
            "success": True,
            "file": signature.signature.url
        },
        status=status.HTTP_200_OK,
    )
