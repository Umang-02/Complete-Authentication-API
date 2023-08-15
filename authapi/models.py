from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
# Create your models here.

#A model based on class for the user
#A custom usermanager model

class UserManager(BaseUserManager):
    def create_user(self,email,name,tc,password=None,password2=None):
    # The method create_user will create and saves a User with the given mail,name,tc and password

        #Raising an exception if no email exist.
        if not email:
            raise ValueError('Users must have an email address')
        
        user=self.model(
            email=self.normalize_email(email),
            name=name,
            tc=tc,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user 
    
    def create_superuser(self,email,name,tc,password=None):

        user=self.create_user(
            email,
            password=password,
            name=name,
            tc=tc,
        )
        user.is_admin=True
        user.save(using=self._db)
        return user
    
#Custom user model

class User(AbstractBaseUser):
    email=models.EmailField(
        verbose_name='Email',
        max_length=255,
        unique=True,
    )
    name=models.CharField(max_length=200)
    tc=models.BooleanField()
    is_active=models.BooleanField(default=True)
    is_admin=models.BooleanField(default=False)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)

    objects=UserManager()

    USERNAME_FIELD='email' #The login will now require email instead of username

    #We need the field email also to be required, but since we have it in the username_field, it is by default a required field.
    REQUIRED_FIELDS=['name','tc']

    def __str__(self):
        return self.email
    
    #The object will appear with email, for this the above method str is used.
    
    @property
    def is_staff(self):
        "Is the user a member of staff?"
        return self.is_admin
    
