from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

# SimpleJWT imports
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import permissions

from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from rest_framework.response import Response

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')

    if not user.check_password(old_password):
        return Response({'error': 'Old password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.save()
    return Response({'message': 'Password changed successfully'})

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    user = request.user
    if request.method == 'GET':
        return Response({
            'username': user.username,
            'email': user.email,
            'name': user.first_name  # or `user.get_full_name()`
        })
    elif request.method == 'PUT':
        user.first_name = request.data.get('name', user.first_name)
        user.save()
        return Response({'message': 'Profile updated'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def active_users(request):
    users = User.objects.filter(is_active=True)
    user_data = [{"id": user.id, "username": user.username} for user in users]
    return Response(user_data)


@api_view(['POST'])
@permission_classes([AllowAny])
def api_register(request):
    data = request.data
    username = data.get('username')
    email = data.get('email')
    password1 = data.get('password1')
    password2 = data.get('password2')
    first_name = data.get('first_name', '')
    last_name = data.get('last_name', '')

    # Check required fields
    if not all([username, email, password1, password2]):
        return Response({'error': 'All fields are required'}, status=status.HTTP_400_BAD_REQUEST)

    # Passwords match?
    if password1 != password2:
        return Response({'error': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)

    # Username and email uniqueness
    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

    # Password validation
    try:
        validate_password(password1)
    except ValidationError as e:
        return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)

    # Create user
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password1,
        first_name=first_name,
        last_name=last_name
    )
    user.save()

    return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)


# JWT customization
class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username
        token['email'] = user.email
        return token


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer
    permission_classes = [permissions.AllowAny]