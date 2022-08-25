from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from .models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'firstName', 'lastName', 'companyName', 'email', 'age', 'password', 'state',
                  'city', 'zip', 'web']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user = User.objects.create(
            firstName = validated_data['firstName'],
            lastName = validated_data['lastName'],
            companyName =validated_data['companyName'],
            email = validated_data['email'],
            age = validated_data['age'],
            password=make_password(validated_data['password']),
            state = validated_data['state'],
            city = validated_data['city'],
            web = validated_data['web'],
            zip = validated_data['zip']
        )
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class UserSearchDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'