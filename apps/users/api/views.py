from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from django.contrib.auth.decorators import login_required
import time


@api_view(["POST"])
@login_required()
def update_profile_picture(request):
    if request.data['photo']:
        time.sleep(2)
        user = request.user
        user.update_profile_photo(request.data['photo'])
        user.save()

        return Response(
            data={
                "success": True,
                "photo": user.photo.url,
                "message": "Photo updated Successfully"
            },
            status=status.HTTP_200_OK,
        )
    else:
        return Response(
            data={
                "success": False,
                'error': "Empty Image Selection"
            },
            status=status.HTTP_200_OK,

        )
