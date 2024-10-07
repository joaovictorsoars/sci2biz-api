from django.http import JsonResponse
from json import loads, JSONDecodeError
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect
from sci2biz_app.models import Users, Roles
from django.contrib.auth.hashers import BCryptSHA256PasswordHasher
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone


@csrf_protect
def login(request):
    if request.method == "POST":
        try:
            data = loads(request.body)
            full_name = data.get("username")
            email = data.get("email")
            password = data.get("password")

            user = Users.objects.get(email=email)

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


@csrf_protect
def register(request):
    if request.method == "POST":
        try:
            data = loads(request.body)
            full_name = data.get("username")
            email = data.get("email")
            password = data.get("password")
            role_name = data.get("role_name")

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

        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "Invalid JSON"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)
        return JsonResponse(
            {
                "message": "Cadastro successful",
                "user": {"full_name": full_name, "email": email, "password": hashed_password},
            }
        )


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


def get_csrf_token(request):
    csrf_token = get_token(request)
    return JsonResponse({"csrfToken": csrf_token})
