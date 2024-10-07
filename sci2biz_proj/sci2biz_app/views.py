from django.http import JsonResponse
from json import loads, JSONDecodeError
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect
from sci2biz_app.models import Users, Roles
from django.contrib.auth.hashers import BCryptSHA256PasswordHasher
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from typing import Tuple, Dict, Union, Any

# Section that handles CSRF token

def get_csrf_token(request):
    csrf_token = get_token(request)
    return JsonResponse({"csrfToken": csrf_token})

# Section DEBUG

def get_user_logged_in(request):
    if request.method == "GET":
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                # Decodificar o token
                decoded_token = UntypedToken(token)
                user_id = decoded_token.get('user_id')
                
                # Obter o usuário a partir do ID
                user = Users.objects.get(id=user_id)
                user_info = {
                    "full_name": user.full_name,
                    "email": user.email
                }
                return JsonResponse({"user": user_info})
            except (InvalidToken, TokenError):
                return JsonResponse({"error": "Invalid Token"}, status=401)
            except Users.DoesNotExist:
                return JsonResponse({"error": "User not found"}, status=404)
        else:
            return JsonResponse({"error": "Authorization not provided"}, status=401)


def verify_user_privileges(request) -> Tuple[bool, Union[str, Dict[str, Any]]]:
    """Verify the user privileges"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]

        try:
            # Decodificar o token
            decoded_token = UntypedToken(token)
            user_id = decoded_token.get('user_id')
            user = Users.objects.get(id=user_id)
            print(user.role_id.role_name)
            print(user.role_id.role_name=='Admin')
            print(user.role_id.role_name=='Professor')
            if user.role_id.role_name not in ['Admin', 'Professor']:
                return False, {"error":"You don't have permissions to do that", "status":403}
        except Users.DoesNotExist:
            return False, {"error":"User not found", "status":404}
    else:
        return False, {"error":"Authorization not provided", "status":401}

    return True, ""


# Section that handles authentication

@csrf_protect
def login(request):
    if request.method == "POST":
        try:
            data = loads(request.body)
            full_name = data.get("username")
            email = data.get("email")
            password = data.get("password")

            if not full_name or not email or not password:
                return JsonResponse({"message": "Missing required fields"}, status=400)

            user = Users.objects.get(email=email)

            if user.full_name != full_name:
                return JsonResponse({"message": "Invalid full name"}, status=400)

            hasher = BCryptSHA256PasswordHasher()

            if not hasher.verify(password, user.password):
                return JsonResponse({"message": "Invalid password"}, status=400)

            if user.is_active:
                user.last_login = timezone.now()
                user.save(update_fields=["last_login"])
                refresh = RefreshToken.for_user(user)
                return JsonResponse(
                    {
                        "message": "Login successful",
                        "user": {"full_name": user.full_name, "email": user.email},
                        "access_token": str(refresh.access_token),
                        "refresh_token": str(refresh),
                    },
                    status=200,
                )
            else:
                return JsonResponse({"message": "User account is disabled"}, status=403)

        except Users.DoesNotExist:
            return JsonResponse({"message": "User not found"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Method not allowed"}, status=405)



# Section that handles CRUD operations

#Create
@csrf_protect
def register(request) -> JsonResponse:
    """Register a new user."""
    if request.method == "POST":
        try:
            data = loads(request.body)
            full_name = data.get("username")
            email = data.get("email")
            password = data.get("password")
            role_name = data.get("role_name")

            if not full_name or not email or not password or not role_name:
                return JsonResponse({"message": "Missing required fields"}, status=400)
            
            if Users.objects.filter(email=email).exists():
                return JsonResponse({"message": "This email is already registered"}, status=400)

            hasher = BCryptSHA256PasswordHasher()
            hashed_password = hasher.encode(password, hasher.salt())

            role_id = Roles.objects.get(role_name=role_name)

            user = Users(
                full_name=full_name,
                email=email,
                role_id=role_id,
                password=hashed_password,
            )
            user.save()

        except Roles.DoesNotExist:
            return JsonResponse({"message": "Role not found"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)
        return JsonResponse(
            {
                "message": "Cadastro successful",
                "user": {
                    "full_name": full_name,
                    "email": email,
                    "password": hashed_password,
                },
            }
        )


#Read
@csrf_protect
def list_users(request) -> JsonResponse:
    """List users."""
    if request.method == "GET":
        users = Users.objects.all()
        users_list = [
            {
                "full_name": user.full_name,
                "email": user.email,
                "role_name": user.role_id.role_name,
            }
            for user in users
        ]
        return JsonResponse({"users": users_list}, status=200)
    else:
        return JsonResponse({"message": "Method not allowed"}, status=405)


#Update
@csrf_protect
def update_user(request) -> JsonResponse:
    """Update user information."""

    if request.method == 'PUT':

        boolean, text = verify_user_privileges(request)
        
        if boolean:
            try:
                data = loads(request.body)
                email = data.get("email")
                full_name = data.get("full_name")
                new_email = data.get("new_email")
                role_name = data.get("role_name")
                
                if not email:
                    return JsonResponse({"message": "Email is required"}, status=400)

                user = Users.objects.get(email=email)

                if full_name:
                    user.full_name = full_name
                if new_email:
                    user.email = new_email
                if role_name:
                    role = Roles.objects.get(role_name=role_name)
                    user.role_id = role

                user.save()
                return JsonResponse({"message": "User updated successfully"}, status=200)

            except Users.DoesNotExist:
                return JsonResponse({"message": "User not found"}, status=404)
            except Roles.DoesNotExist:
                return JsonResponse({"message": "Role not found"}, status=404)
            except (KeyError, JSONDecodeError):
                return JsonResponse({"message": "Invalid JSON"}, status=400)
            except Exception as e:
                return JsonResponse({"message": str(e)}, status=400)
        else:
            if text:
                return JsonResponse({"error":text["error"]}, status=text["status"])

    else:
        return JsonResponse({"message": "Method not allowed"}, status=405)


#Delete
@csrf_protect
def remove_user(request) -> JsonResponse:
    """Remove a user."""

    if request.method == "DELETE":

        boolean, text = verify_user_privileges(request)

        if boolean:
            try:
                data = loads(request.body)
                email = data.get("email")

                if not email:
                    return JsonResponse({"message": "Email is required"}, status=400)

                user = Users.objects.get(email=email)
                user.delete()
                return JsonResponse({"message": "User deleted successfully"}, status=200)

            except Users.DoesNotExist:
                return JsonResponse({"message": "User not found"}, status=404)
            except (KeyError, JSONDecodeError):
                return JsonResponse({"message": "Invalid JSON"}, status=400)
            except Exception as e:
                return JsonResponse({"message": str(e)}, status=400)
        if text:
                return JsonResponse({"error":text["error"]}, status=text["status"])

    else:
        return JsonResponse({"message": "Method not allowed"}, status=405)



# Section that handles password reset

@csrf_protect
def change_password(request) -> JsonResponse:
    """Change user password, most simple than the other functions here."""
    if request.method == "POST":
        try:
            data = loads(request.body)
            email = data.get("email")
            current_password = data.get("current_password")
            new_password = data.get("new_password")

            if not email or not current_password or not new_password:
                return JsonResponse({"message": "Missing required fields"}, status=400)

            user = Users.objects.get(email=email)
            hasher = BCryptSHA256PasswordHasher()

            if not hasher.verify(current_password, user.password):
                return JsonResponse({"message": "Invalid current password"}, status=400)

            # Verifique se a nova senha atende aos requisitos (exemplo simples)
            if len(new_password) < 8:
                return JsonResponse({"message": "New password must be at least 8 characters long"}, status=400)

            # Atualize a senha do usuário
            user.password = hasher.encode(new_password, hasher.salt())
            user.save(update_fields=["password"])

            return JsonResponse({"message": "Password changed successfully"}, status=200)

        except Users.DoesNotExist:
            return JsonResponse({"message": "User not found"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Method not allowed"}, status=405)


# Section that handles password reset with smtp (send email)

@csrf_protect
def request_password_reset(request) -> JsonResponse:
    """Request a password reset."""
    if request.method == "POST":
        try:
            data = loads(request.body)
            email = data.get("email")

            if not email:
                return JsonResponse({"message": "Email is required"}, status=400)

            user = Users.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = request.build_absolute_uri(reverse('password_reset_confirm', args=[uid, token]))
            message = f"Click the link below to reset your password:\n{reset_url}"
            send_mail('Password Reset Request', message, settings.DEFAULT_FROM_EMAIL, [email])
            return JsonResponse({"message": "Password reset email sent"}, status=200)

        except Users.DoesNotExist:
            return JsonResponse({"message": "User not found"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Method not allowed"}, status=405)

@csrf_protect
def confirm_password_reset(request, uidb64, token) -> JsonResponse:
    """Confirm the password reset."""
    if request.method == "POST":
        try:
            data = loads(request.body)
            new_password = data.get("new_password")

            if not new_password:
                return JsonResponse({"message": "New password is required"}, status=400)

            uid = force_str(urlsafe_base64_decode(uidb64))
            user = Users.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                hasher = BCryptSHA256PasswordHasher()
                user.password = hasher.encode(new_password, hasher.salt())
                user.save(update_fields=["password"])
                return JsonResponse({"message": "Password has been reset"}, status=200)
            else:
                return JsonResponse({"message": "Invalid token"}, status=400)

        except Users.DoesNotExist:
            return JsonResponse({"message": "User not found"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Method not allowed"}, status=405)


# Section that handles role registration

@csrf_protect
def register_role(request):
    if request.method == "POST":
        try:
            data = loads(request.body)
            role_name = data.get("role_name")
            role = Roles(role_name=role_name)
            role.save()

        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)
        return JsonResponse({"message": "Role registered", "role_name": role_name})
    

