from django.forms import ValidationError
from rest_framework import serializers
from authapi.models import User
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

#Serializer to handle a new user registration.
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['email','name','password','password2','tc']
        extra_kwargs={
            'password':{'write_only':True}
        }
    
    #Validating the password and confirm password while a user is registering using the below function.
    
    def validate(self,data):
        #Retrieving the password and password2 from the data recieved to the serializer from the post request sent
        password=data.get('password')
        password2=data.get('password2')
        if(password!=password2):
            raise serializers.ValidationError("Passwords doesn't match")
        return data
    
    def create(self,validate_data):
        return User.objects.create_user(**validate_data)
    
class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email','password',]

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id','email','name']

class UserChangePasswordSerializer(serializers.ModelSerializer):
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['password','password2']
    def validate(self,attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user=self.context.get('user')
        if password!=password2:
            raise serializers.ValidationError("Passwords doesn't match")
        user.set_password(password)
        user.save()
        return attrs
    
class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email']
    def validate(self,attrs):
        email=attrs.get('email')
        if User.objects.filter(email=email).exists():
            user=User.objects.get(email=email)
            uid=urlsafe_base64_encode(force_bytes(user.id))
            print(f'Encoded uid:{uid}')
            token=PasswordResetTokenGenerator().make_token(user)
            print(f'password reset token:{token}')
            link='http://localhost:3000/api/user/reset/'+uid+'/'+token
            print(f'Password reset link:{link}')
            #Send email
            return attrs
        else:
            raise ValueError("The User hasn't been registered")

class UserPasswordResetSerializer(serializers.ModelSerializer):
    password=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    password2=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    class Meta:
        model=User
        fields=['password','password2']
    def validate(self,attrs):
        try:
            password=attrs.get('password')
            password2=attrs.get('password2')
            uid=self.context.get('uid')
            token=self.context.get('token')
            if password!=password2:
                raise serializers.ValidationError("Passwords doesn't match")
            id=smart_str(urlsafe_base64_decode(uid))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise ValidationError('Token is incorrect or expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user,token)