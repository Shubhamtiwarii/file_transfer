# fileshare_app/views.py

import os
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from django.urls import reverse
from django.utils.http import urlencode
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from .models import File
from .serializers import FileSerializer
from rest_framework.authtoken.models import Token
#Ops User APIs

@api_view(['POST'])
def ops_user_login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    
    user = authenticate(request, username=username, password=password)
    
    if user is not None and user.is_staff:
        login(request, user)
        token, created = Token.objects.get_or_create(user=user)
        return JsonResponse({'message': 'Login successful','token': token.key},status=400)
        
    else:
        return JsonResponse({'error': 'Invalid credentials'}, status=400)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def ops_user_upload_file(request):
    if request.user.is_staff:
        file = request.FILES.get('file')
        if file:
            file_extension = os.path.splitext(file.name)[1].lower()
            if file_extension in ['.pptx', '.docx', '.xlsx']:
                new_file = File(owner=request.user, file=file)
                new_file.save()
                return JsonResponse({'message': 'File uploaded successfully'})
            else:
                return JsonResponse({'error': 'File type not allowed'}, status=400)
        else:
            return JsonResponse({'error': 'No file uploaded'}, status=400)
    else:
        return JsonResponse({'error': 'Permission denied'}, status=403)

#Client User API

@api_view(['POST'])
def client_user_signup(request):
    # Get user data from request
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    
    # Check if username or email already exists
    if User.objects.filter(username=username).exists():
        return JsonResponse({'error': 'Username already exists'}, status=400)
    
    if User.objects.filter(email=email).exists():
        return JsonResponse({'error': 'Email already registered'}, status=400)
    
    
    new_user = User.objects.create_user(username=username, email=email, password=password)
    new_user.is_active = False  # User is not active until email is verified
    new_user.save()
    
    
    verification_token = new_user.username  
    verification_url = request.build_absolute_uri(reverse('client_user_email_verify')) + '?' + urlencode({'token': verification_token})
    
   
    send_mail(
        'Verify your email',
        f'Click the link to verify your email: {verification_url}',
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )
    
    return JsonResponse({'message': 'Verification email sent'})

@api_view(['GET'])
def client_user_email_verify(request):
    token = request.GET.get('token')
    if token:
        try:
            user = User.objects.get(username=token)
            user.is_active = True
            user.save()
            return JsonResponse({'message': f'Email {user.email} verified successfully'})
        except User.DoesNotExist:
            return JsonResponse({'error': 'Invalid token'}, status=400)
    else:
        return JsonResponse({'error': 'Token parameter is missing'}, status=400)

@api_view(['POST'])
def client_user_login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    
    user = authenticate(request, username=username, password=password)
    
    if user is not None and user.is_active:
        login(request, user)
        token, created = Token.objects.get_or_create(user=user)
        return JsonResponse({'message': 'Login successful','token': token.key}, status=400)
        # return JsonResponse({'message': 'Login successful'})
    else:
        return JsonResponse({'error': 'Invalid credentials'}, status=400)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def client_user_list_files(request):
    # files=File.objects.all()
    files = File.objects.filter(owner=request.user)
    serializer = FileSerializer(files, many=True)
    return JsonResponse(serializer.data, safe=False)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def client_user_download_file(request, file_id):
    file = get_object_or_404(File, id=file_id)
    # if request.user == file.owner:
    user=request.user
    token, created = Token.objects.get_or_create(user=user)
    if request.user:
        # download_link = f"https://example.com/download/{file.id}/{token.key}"
        download_link = f"https://127.0.0.1:8000/download-file/{token.key}"
        return JsonResponse({'download_link': download_link, 'message': 'success'})
    else:
        return JsonResponse({'error': 'Permission denied'}, status=403)
