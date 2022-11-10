from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.urls import reverse


class UserProfileManager(BaseUserManager):

    def create_user(self, email, username, password=None):
        if not email:  # validating email
            raise ValueError('EMAIL IS REQUIRED!!')
        if not username:  # validating username
            raise ValueError('USERNAME IS REQUIRED!!')

        email = self.normalize_email(email)  # normalizing the email
        user = self.model(email=email, username=username)  # creating user
        user.set_password(password)  # making the password hashed
        user.save(using=self._db)  # saving the user object

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

    class Meta:
        ordering = ('username',)


