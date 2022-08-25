import jwt
from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import update_last_login
from django.db.models import Q
from rest_framework import status
from rest_framework.generics import CreateAPIView, RetrieveAPIView, UpdateAPIView, DestroyAPIView, ListAPIView, ListCreateAPIView
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
import io
from rest_framework.pagination import PageNumberPagination
from rest_framework import filters
from admin_apis import settings
from .models import User
from .serializers import (UserRegistrationSerializer, UserProfileSerializer, UserSearchDetailsSerializer)


# Create your views here
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(CreateAPIView):
    permission_classes = (AllowAny,)
    UserRegistrationSerializer = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        try:
            pythonData = JSONParser().parse(io.BytesIO(request.body))
            firstName = pythonData.get('firstName', False)
            lastName = pythonData.get('lastName', False)
            companyName = pythonData.get('companyName', False)
            email = pythonData.get('email', False)
            age = pythonData.get('age', False)
            state = pythonData.get('state', False)
            city = pythonData.get('city', False)
            zip = pythonData.get('zip', False)
            web = pythonData.get('web', False)
            password = pythonData.get('password', False)
            if not firstName:
                response = {
                    "error":{
                        "errorCode": 501,
                        "statusCode": status.HTTP_400_BAD_REQUEST,
                        "errorMessage": "firstname field is required."
                    },
                    "response": None
                }
                return Response(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not lastName:
                response = {
                    "error": {
                        "errorCode": 502,
                        "statusCode": status.HTTP_400_BAD_REQUEST,
                        "errorMessage": "lastname field is required."
                    },
                    "response": None
                }
                return Response(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not companyName:
                response = {
                    "error": {
                        "errorCode": 503,
                        "statusCode": status.HTTP_400_BAD_REQUEST,
                        "errorMessage": "company name field is required."
                    },
                    "response": None
                }
                return Response(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not age:
                response = {
                    "error": {
                        "errorCode": 504,
                        "statusCode": status.HTTP_400_BAD_REQUEST,
                        "errorMessage": "age field is required."
                    },
                    "response": None
                }
                return Response(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not state:
                response = {
                    "error": {
                        "errorCode": 505,
                        "statusCode": status.HTTP_400_BAD_REQUEST,
                        "errorMessage": "state field is required."
                    },
                    "response": None
                }
                return Response(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not email:
                response = {
                    "error":{
                        "errorCode": 506,
                        "statusCode": status.HTTP_400_BAD_REQUEST,
                        "errorMessage": "email field is required."
                    },
                    "response": None
                }
                return Response(response,status.HTTP_422_UNPROCESSABLE_ENTITY)
            if (User.objects.filter(Q(email=email)).exists()):
                response = {
                    "error": {
                        "errorCode": 511,
                        "statusCode": status.HTTP_400_BAD_REQUEST,
                        "errorMessage": "mobileNo/email is already exists."
                    },
                    "response": None
                }
                return Response(response, status.HTTP_400_BAD_REQUEST)
            if not password:
                response = {
                    "error":{
                        "errorCode": 507,
                        "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "errorMessage": "password field is required."
                    },
                    "response": None
                }
                return Response(response,status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not city:
                response = {
                    "error":{
                        "errorCode": 508,
                        "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "errorMessage": "city field is required."
                    },
                    "response": None
                }
                return Response(response,status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not zip:
                response = {
                    "error":{
                        "errorCode": 509,
                        "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "errorMessage": "zip field is required."
                    },
                    "response": None
                }
                return Response(response,status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not web:
                response = {
                    "error":{
                        "errorCode": 510,
                        "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "errorMessage": "web field is required."
                    },
                    "response": None
                }
                return Response(response,status.HTTP_422_UNPROCESSABLE_ENTITY)

            serializer = UserRegistrationSerializer(data=pythonData)
            if serializer.is_valid(raise_exception=True):
                user = serializer.save()
                data = {
                    "userId": user.id,
                    "firstName": user.firstName,
                    "lastName": user.lastName,
                    "companyName": user.companyName,
                    "email": user.email,
                    "age": user.age,
                    "state": user.state,
                    "city": user.city,
                    "zip": user.zip,
                    "web": user.web,
                    "token": get_tokens_for_user(user)
                }
                response = {
                    "error": None,
                    "response": {
                        "data": data,
                        "message": {
                            'success': True,
                            "successCode": 101,
                            "statusCode": status.HTTP_201_CREATED,
                            "successMessage": "User registered successfully."
                        }
                    }
                }
                return Response(response, status=status.HTTP_201_CREATED)
            else:
                response = {
                    "error": {
                        "errorCode": 515,
                        "statusCode": status.HTTP_400_BAD_REQUEST,
                        "errorMessage": "failed while registering User."
                    },
                    "response": None
                }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            response = {
                "error": {
                    "errorCode": 522,
                    "statusCode": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "errorMessage": str(e)
                },
                "response": None
            }
            return Response(response, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLoginView(RetrieveAPIView):
    permission_classes = (AllowAny,)
    queryset = ''

    def post(self,request):
        try:
            pythonData = JSONParser().parse(io.BytesIO(request.body))
            email = pythonData.get('email', False)
            password = pythonData.get('password', False)
            if not email:
                response = {
                    "error": {
                        "errorCode": 503,
                        "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "errorMessage": "Email field is required to login"
                    },
                    "response": None
                }
                return Response(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
            if not password:
                response = {
                    "error": {
                        "errorCode": 504,
                        "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "errorMessage": "password field is required to login"
                    },
                    "response": None
                }
                return Response(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
            user = User.objects.filter(Q(email=email)).first()
            if user is None:
                response = {
                    "error": {
                        "errorCode": 505,
                        "statusCode": status.HTTP_404_NOT_FOUND,
                        "errorMessage": "Invalid email/password"
                    }
                }
                return Response(response, status=status.HTTP_404_NOT_FOUND)
            if not user.check_password(request.data['password']):
                response = {
                    "error": {
                        "errorCode": 506,
                        "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "errorMessage": "Please enter correct password"
                    },
                    "response": None
                }
                return Response(response, status.HTTP_422_UNPROCESSABLE_ENTITY)
            update_last_login(None, user)
            data = {
                "userId": user.id,
                "email": user.email,
                "token": get_tokens_for_user(user)
            }
            response = {
                "error": None,
                "response": {
                    "data": data,
                    "message": {
                        'success': True,
                        "successCode": 102,
                        "statusCode": status.HTTP_200_OK,
                        "successMessage": "Logged in successfully."
                    }
                }
            }
            return Response(response, status=status.HTTP_200_OK)
        except Exception as e:
            response = {
                "error": {
                    "errorCode": 522,
                    "statusCode": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "errorMessage": str(e)
                },
                "response": None
            }
            return Response(response, status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserLogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            pythonData = JSONParser().parse(io.BytesIO(request.body))
            refreshToken = pythonData.get('refresh', False)
            if not refreshToken:
                response = {
                    "error": {
                        "errorCode": 502,
                        "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                        "errorMessage": "Refresh Token is required to logout!"
                    },
                    "response": None
                }
                return Response(response, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

            token = RefreshToken(refreshToken)
            token.blacklist()
            response = {
                "error": None,
                "response": {
                    "message": {
                        'success': True,
                        "successCode": 102,
                        "statusCode": status.HTTP_205_RESET_CONTENT,
                        "successMessage": "Logout successfully."
                    }
                }
            }
            return Response(response, status=status.HTTP_200_OK)
        except Exception as exception:
            response = {
                "error": {
                    "errorCode": 511,
                    "statusCode": status.HTTP_400_BAD_REQUEST,
                    "errorMessage": str(exception)
                },
                "response": None
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class UserDetailsView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    UserRegistrationSerializer = UserRegistrationSerializer

    def get(self, request):
        try:
            token = request.META.get(
                'HTTP_AUTHORIZATION', " ").split(' ')[1]
            userId = jwt.decode(token, key=settings.SECRET_KEY, algorithms=['HS256', ])
            id = userId['user_id']
            user_id = User.objects.filter(id=id).first()
            queryset = User.objects.all()
            user = get_object_or_404(queryset, pk=id)
            serializer = UserRegistrationSerializer(user)
            detail = serializer.data
            response = {
                "error": None,
                "response": {
                    "data": detail,
                    "message": {
                        'success': True,
                        "successCode": 101,
                        "statusCode": status.HTTP_200_OK,
                        "successMessage": "User detail successfully."
                    }
                }
            }
            return Response(response, status=status.HTTP_200_OK)

        except Exception as e:
            response = {
                "error": {
                    "errorCode": 522,
                    "statusCode": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "errorMessage": str(e)
                },
                "response": None
            }
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UpdateProfileView(UpdateAPIView):
    permission_classes = (AllowAny,)
    def get_objects(self, pk):
        return User.objects.get(pk=pk)

    def put(self, request, pk):
        try:
            user = self.get_objects(pk)
            serializer = UserProfileSerializer(user, data=request.data)
            if serializer.is_valid():
                serializer.save()
                user = User.objects.get(id=pk)
                user.save()
                response = {
                    "error": None,
                    "response": {
                        "message": {
                            'success': True,
                            "successCode": 102,
                            "statusCode": status.HTTP_200_OK,
                            "successMessage": "User updated successfully."
                        }
                    }
                }
                return Response(response, status=status.HTTP_200_OK)
            else:
                response = {
                    "error": {
                        "errorCode": 506,
                        "statusCode": status.HTTP_404_NOT_FOUND,
                        "errorMessage": "Error while updating user"
                    },
                    "response": None
                }
                return Response(response, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            response = {
                "error": {
                    "errorCode": 522,
                    "statusCode": status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "errorMessage" : str(e)
                },
                "response": None
            }
            return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ListUserAPIView(ListAPIView):
    permission_classes = (AllowAny, )
    UserProfileSerializer = UserProfileSerializer
    queryset = User
    pagination_class = 10

    def get(self, request, *args, **kwargs):
        user = User.objects.filter(Q(is_superuser=False)).all().order_by('-firstName')
        serializer = UserProfileSerializer(user, many=True)
        response = {
            "error": None,
            "response": {
                "data": serializer.data,
                "message": {
                    'success': True,
                    "successCode": 101,
                    "statusCode": status.HTTP_201_CREATED,
                    "successMessage": "User data fetch successfully."
                }
            }
        }
        return Response(response, status=status.HTTP_201_CREATED)


class DeleteUserView(DestroyAPIView):
    permission_classes = (AllowAny ,)
    queryset = User

    def delete(self, request, id):
        if not User.objects.filter(id=id).exists():
            response = {
                "error": {
                    "errorCode": 501,
                    "statusCode": status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "errorMessage": "User not exists"
                },
                "response": None
            }
            return Response(response, status=status.HTTP_422_UNPROCESSABLE_ENTITY)

        t = User.objects.get(id=id).delete()
        if t:
            response = {
                "error": None,
                "response": {
                    "message": {
                        'success': True,
                        "successCode": 102,
                        "statusCode": status.HTTP_200_OK,
                        "successMessage": "User delete successfully."
                    }
                }
            }
            return Response(response, status=status.HTTP_200_OK)
        else:
            response = {
                "error": {
                    "errorCode": 506,
                    "statusCode": status.HTTP_404_NOT_FOUND,
                    "errorMessage": "Error while deleting user"
                },
                "response": None
            }
            return Response(response, status=status.HTTP_404_NOT_FOUND)


class UserSearchView(ListCreateAPIView):
    permission_classes = (AllowAny,)

    filter_backends = (filters.SearchFilter,)
    queryset = User.objects.all()
    serializer_class = UserSearchDetailsSerializer
    search_fields = ['firstName']

    def get(self, request):
        try:
            qs = super().get_queryset()
            search = str(self.request.query_params.get('search')).lower()
            queryset = qs.filter((Q(firstName__istartswith=search)) & Q(is_superuser=False))
            serializer = UserSearchDetailsSerializer(queryset, many=True)

            finalData = []
            for details in serializer.data:
                serializerData = {
                    'id': details['id'],
                    'firstName': details['firstName'],
                    'lastName': details['lastName'],
                    'companyName': details['companyName'],
                    'email': details['email'],
                    'state': details['state'],
                    'city':  details['city'],
                    'zip': details['zip'],
                    'web': details['web'],
                    'age': details['age']
                }
                finalData.append(serializerData)
                print(finalData)
            response = {
                "error": None,
                "response": {
                    "data": finalData,
                    "message": {
                        'success': True,
                        "successCode": 102,
                        "statusCode": status.HTTP_200_OK
                    }
                }
            }
            return Response(response, status=status.HTTP_200_OK)
        except Exception as exception:
            response = {
                "error": {
                    "errorCode": 511,
                    "statusCode": status.HTTP_400_BAD_REQUEST,
                    "errorMessage": str(exception)
                },
                "response": None
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

