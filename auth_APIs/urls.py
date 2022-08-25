from django.urls import path
from auth_APIs.views import (UserRegistrationView, UserLoginView, UserLogoutView, UpdateProfileView,
                             UserDetailsView, ListUserAPIView, DeleteUserView, UserSearchView)
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('token', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
    path('user/registration', UserRegistrationView.as_view(),name='register'),
    path('user/login', UserLoginView.as_view(), name='login'),
    path('user/logout', UserLogoutView.as_view(), name='logout'),
    path('user/update/<int:pk>', UpdateProfileView.as_view(), name='update'),
    path('user/details', UserDetailsView.as_view()),
    path('user/list', ListUserAPIView.as_view()),
    path('user/search', UserSearchView.as_view()),
    path('user/delete/<int:id>', DeleteUserView.as_view()),
]
