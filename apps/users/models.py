from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.urls import reverse
import os
from django.db import IntegrityError


class UserProfileManager(BaseUserManager):

    def create_user(self,
                    email,
                    username,
                    first_name=None, surname=None,
                    appointment=None, photo=None,
                    password=None, ):
        if not email:  # validating email
            raise ValueError('EMAIL IS REQUIRED!!')
        if not username:  # validating username
            raise ValueError('USERNAME IS REQUIRED!!')

        if not first_name:  # validating first_name
            raise ValueError('First Name IS REQUIRED!!')

        if not surname:  # validating surname
            raise ValueError('Surname IS REQUIRED!!')

        if not appointment:  # validating appointment
            raise ValueError('Please enter your appointment')

        if not photo:  # validating photo
            raise ValueError('Profile Photo IS REQUIRED!!')

        email = self.normalize_email(email)  # normalizing the email
        user = self.model(email=email, username=username)  # creating user
        user.set_password(password)  # making the password hashed
        user.surname = surname
        user.first_name = first_name
        user.appointment = appointment
        user.photo = photo

        try:
            user.save(using=self._db)  # saving the user object
        except IntegrityError:
            raise IntegrityError('Email or Username Already Exists!!')

        return user

    """
    Function for creation of a superuser
    """

    def create_superuser(self, email, username, password):

        user = self.create_user(email=email, username=username, password=password)

        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(max_length=255, unique=True)

    first_name = models.CharField(max_length=255, null=True, blank=True)
    surname = models.CharField(max_length=255, null=True, blank=True)

    photo = models.ImageField(upload_to='image/', null=True)
    appointment = models.CharField(max_length=255, default="Special Assistant")

    is_active = models.BooleanField(default=True)

    objects = UserProfileManager()  # creating a profile manager for controlling the users model via command line

    USERNAME_FIELD = 'email'  # overriding the username field and using the email field for authentication
    EMAIL_FIELD = 'email'

    REQUIRED_FIELDS = ['username']  # A list of Fields that are required for user creation

    ''' Creating a string representation of the user model '''
    def __str__(self):
        return self.username

    def update_profile_photo(self, photo):
        if self.photo:
            os.remove(self.photo.path)
        self.photo = photo

    class Meta:
        ordering = ('username',)
