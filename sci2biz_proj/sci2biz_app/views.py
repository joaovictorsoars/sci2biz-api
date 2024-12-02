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
from rest_framework import viewsets
from .models import Users, Demanda, Turma
from .serializers import UserSerializer
from rest_framework.decorators import api_view, schema, authentication_classes, permission_classes


class UserViewSet(viewsets.ModelViewSet):
    queryset = Users.objects.all()
    serializer_class = UserSerializer


# Section that handles CSRF token

def get_csrf_token(request):
    csrf_token = get_token(request)
    return JsonResponse({"csrfToken": csrf_token})

# Section DEBUG

def get_user_logged_in(request):
    if request.method == "GET":
        auth_header = request.headers.get('Authorization')
        if (auth_header and auth_header.startswith('Bearer ')):
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
                return JsonResponse({"error": "Token inválido"}, status=401)
            except Users.DoesNotExist:
                return JsonResponse({"error": "Usuário não encontrado"}, status=404)
        else:
            return JsonResponse({"error": "Autorização não fornecida"}, status=401)


def verify_user_privileges(request) -> Tuple[bool, Union[str, Dict[str, Any]]]:
    """Verify the user privileges"""
    auth_header = request.headers.get('Authorization')
    if (auth_header and auth_header.startswith('Bearer ')):
        token = auth_header.split(' ')[1]
        try:
            # Decodificar o token
            decoded_token = UntypedToken(token)
            user_id = decoded_token.get('user_id')
            user = Users.objects.get(id=user_id)
            if (user.role_id.role_name not in ['Admin', 'Professor']):
                return False, {"error":"Você não tem permissão para fazer isso", "status":403}
        except Users.DoesNotExist:
            return False, {"error":"Usuário não encontrado", "status":404}
    else:
        return False, {"error":"Autorização não fornecida", "status":401}

    return True, ""

# Section that handles token refresh
@api_view(['POST'])
@csrf_protect
def refresh_token(request):
    """Refresh the user token."""
    if request.method == "POST":
        try:
            refresh_input = request.headers.get('Authorization')
            if (refresh_input and refresh_input.startswith('Bearer ')):
                refresh = refresh_input.split(' ')[1]

                refresh = RefreshToken(refresh)

                user_id = refresh.get('user_id')
                user = Users.objects.get(id=user_id)

                if (user.refresh_token != str(refresh)):
                    return JsonResponse({"message": "Token de atualização inválido"}, status=400)

                new_refresh = RefreshToken.for_user(user)
                user.refresh_token = new_refresh
                user.save(update_fields=["refresh_token"])

                return JsonResponse({"access_token": str(new_refresh.access_token), "refresh_token": str(new_refresh)}, status=200)
            else:
                return JsonResponse({"message": "Token de atualização é necessário"}, status=400)

        except Users.DoesNotExist:
            return JsonResponse({"message": "Usuário não encontrado"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "JSON inválido"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)

# Section that handles authentication
@api_view(['POST'])
@permission_classes([])
@csrf_protect
def login(request) -> JsonResponse:
    """Login a user."""
    if request.method == "POST":
        try:
            data = request.data
            email = data.get("email")
            password = data.get("password")

            if (not email or not password):
                return JsonResponse({"message": "Campos obrigatórios faltando"}, status=400)

            user = Users.objects.get(email=email)

            hasher = BCryptSHA256PasswordHasher()

            if (not hasher.verify(password, user.password)):
                return JsonResponse({"message": "Senha inválida"}, status=400)

            if user.is_active:
                user.last_login = timezone.now()
                refresh = RefreshToken.for_user(user)
                user.refresh_token = refresh
                user.save(update_fields=["last_login", "refresh_token"])

                return JsonResponse(
                    {
                        "message": "Login bem-sucedido",
                        "user": {"full_name": user.full_name, "email": user.email},
                        "access_token": str(refresh.access_token),
                        "refresh_token": str(refresh),
                    },
                    status=200,
                )
            else:
                return JsonResponse({"message": "Conta de usuário desativada"}, status=403)

        except Users.DoesNotExist:
            return JsonResponse({"message": "Usuário não encontrado"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "JSON inválido"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)



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

            if (not full_name or not email or not password or not role_name):
                return JsonResponse({"message": "Campos obrigatórios faltando"}, status=400)
            
            if Users.objects.filter(email=email).exists():
                return JsonResponse({"message": "Este email já está registrado"}, status=400)

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
            return JsonResponse({"message": "Função não encontrada"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "JSON inválido"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)
        return JsonResponse(
            {
                "message": "Cadastro bem-sucedido",
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
        return JsonResponse({"message": "Método não permitido"}, status=405)


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
                    return JsonResponse({"message": "Email é obrigatório"}, status=400)

                user = Users.objects.get(email=email)

                if full_name:
                    user.full_name = full_name
                if new_email:
                    user.email = new_email
                if role_name:
                    role = Roles.objects.get(role_name=role_name)
                    user.role_id = role

                user.save()
                return JsonResponse({"message": "Usuário atualizado com sucesso"}, status=200)

            except Users.DoesNotExist:
                return JsonResponse({"message": "Usuário não encontrado"}, status=404)
            except Roles.DoesNotExist:
                return JsonResponse({"message": "Função não encontrada"}, status=404)
            except (KeyError, JSONDecodeError):
                return JsonResponse({"message": "JSON inválido"}, status=400)
            except Exception as e:
                return JsonResponse({"message": str(e)}, status=400)
        else:
            if text:
                return JsonResponse({"error":text["error"]}, status=text["status"])

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)


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
                    return JsonResponse({"message": "Email é obrigatório"}, status=400)

                user = Users.objects.get(email=email)
                user.delete()
                return JsonResponse({"message": "Usuário deletado com sucesso"}, status=200)

            except Users.DoesNotExist:
                return JsonResponse({"message": "Usuário não encontrado"}, status=404)
            except (KeyError, JSONDecodeError):
                return JsonResponse({"message": "JSON inválido"}, status=400)
            except Exception as e:
                return JsonResponse({"message": str(e)}, status=400)
        if text:
                return JsonResponse({"error":text["error"]}, status=text["status"])

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)


# Section that handles user active status

@csrf_protect
def toggle_user_active_status(request) -> JsonResponse:
    """Toggle user active status."""

    if request.method == "PUT":

        boolean, text = verify_user_privileges(request)

        if boolean:
            try:
                data = loads(request.body)
                email = data.get("email")

                if not email:
                    return JsonResponse({"message": "Email é obrigat��rio"}, status=400)

                user = Users.objects.get(email=email)
                user.is_active = not user.is_active
                user.save(update_fields=["is_active"])
                return JsonResponse({"message": "Status de atividade do usuário alterado com sucesso"}, status=200)

            except Users.DoesNotExist:
                return JsonResponse({"message": "Usuário não encontrado"}, status=404)
            except (KeyError, JSONDecodeError):
                return JsonResponse({"message": "JSON inválido"}, status=400)
            except Exception as e:
                return JsonResponse({"message": str(e)}, status=400)
        if text:
                return JsonResponse({"error":text["error"]}, status=text["status"])

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405) 


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

            if (not email or not current_password or not new_password):
                return JsonResponse({"message": "Campos obrigatórios faltando"}, status=400)

            user = Users.objects.get(email=email)
            hasher = BCryptSHA256PasswordHasher()

            if (not hasher.verify(current_password, user.password)):
                return JsonResponse({"message": "Senha atual inválida"}, status=400)

            # Verifique se a nova senha atende aos requisitos (exemplo simples)
            if (len(new_password) < 8):
                return JsonResponse({"message": "A nova senha deve ter pelo menos 8 caracteres"}, status=400)

            # Atualize a senha do usuário
            user.password = hasher.encode(new_password, hasher.salt())
            user.save(update_fields=["password"])

            return JsonResponse({"message": "Senha alterada com sucesso"}, status=200)

        except Users.DoesNotExist:
            return JsonResponse({"message": "Usuário não encontrado"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "JSON inválido"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)


# Section that handles password reset with smtp (send email)

@csrf_protect
def request_password_reset(request) -> JsonResponse:
    """Request a password reset."""
    if request.method == "POST":
        try:
            data = loads(request.body)
            email = data.get("email")

            if not email:
                return JsonResponse({"message": "Email é obrigatório"}, status=400)

            user = Users.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = request.build_absolute_uri(reverse('password_reset_confirm', args=[uid, token]))
            message = f"Clique no link abaixo para redefinir sua senha:\n{reset_url}"
            send_mail('Solicitação de Redefinição de Senha', message, settings.DEFAULT_FROM_EMAIL, [email])
            return JsonResponse({"message": "Email de redefinição de senha enviado"}, status=200)

        except Users.DoesNotExist:
            return JsonResponse({"message": "Usuário não encontrado"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "JSON inválido"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)

@csrf_protect
def confirm_password_reset(request, uidb64, token) -> JsonResponse:
    """Confirm the password reset."""
    if request.method == "POST":
        try:
            data = loads(request.body)
            new_password = data.get("new_password")

            if not new_password:
                return JsonResponse({"message": "A nova senha é obrigatória"}, status=400)

            uid = force_str(urlsafe_base64_decode(uidb64))
            user = Users.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                hasher = BCryptSHA256PasswordHasher()
                user.password = hasher.encode(new_password, hasher.salt())
                user.save(update_fields=["password"])
                return JsonResponse({"message": "Senha redefinida com sucesso"}, status=200)
            else:
                return JsonResponse({"message": "Token inválido"}, status=400)

        except Users.DoesNotExist:
            return JsonResponse({"message": "Usuário não encontrado"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "JSON inválido"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)


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
            return JsonResponse({"message": "JSON inválido"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)
        return JsonResponse({"message": "Função registrada", "role_name": role_name})


@csrf_protect
def create_demanda(request) -> JsonResponse:
    """Create a new Demanda."""
    if request.method == "POST":
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                # Decodificar o token
                decoded_token = UntypedToken(token)
                user_id = decoded_token.get('user_id')
                
                # Obter o usuário a partir do ID
                user = Users.objects.get(id=user_id)
                
                if user.role_id.role_name != 'Professor':
                    return JsonResponse({"error": "Acesso negado. Apenas Professores podem criar demandas."}, status=403)
                
                data = loads(request.body)
                disciplina = data.get("disciplina")
                conteudo = data.get("conteudo")
                tipo_demanda = data.get("tipo_demanda")

                if not disciplina or not conteudo or not tipo_demanda:
                    return JsonResponse({"message": "Campos obrigatórios faltando"}, status=400)

                tipos_validos = {"Extensão", "Ensino", "Pesquisa"}
                if not set(tipo_demanda).issubset(tipos_validos):
                    return JsonResponse({"message": "Tipo de demanda inválido"}, status=400)

                demanda = Demanda(
                    disciplina=disciplina,
                    conteudo=conteudo,
                    indicacao_ativa=False,  # Demanda não ativa até resposta do Administrador
                    professor_responsavel=user,
                )
                demanda.save()

                # Enviar email para o Administrador
                admin_emails = Users.objects.filter(role_id__role_name='Admin').values_list('email', flat=True)
                email_subject = 'Nova Demanda Cadastrada'
                email_body = (
                    f'Uma nova demanda foi cadastrada por {user.full_name}.\n\n'
                    f'Disciplina: {disciplina}\n'
                    f'Conteúdo: {conteudo}\n'
                    f'Tipo(s) de Demanda: {", ".join(tipo_demanda)}\n\n'
                    'Por favor, revise a demanda e responda para ativá-la.'
                )
                send_mail(
                    email_subject,
                    email_body,
                    settings.DEFAULT_FROM_EMAIL,
                    admin_emails
                )

                return JsonResponse({"message": "Demanda criada com sucesso"}, status=201)

            except (InvalidToken, TokenError):
                return JsonResponse({"error": "Token inválido"}, status=401)
            except Users.DoesNotExist:
                return JsonResponse({"error": "Usuário não encontrado"}, status=404)
            except (KeyError, JSONDecodeError):
                return JsonResponse({"message": "JSON inválido"}, status=400)
            except Exception as e:
                return JsonResponse({"message": str(e)}, status=400)
        else:
            return JsonResponse({"error": "Autorização não fornecida"}, status=401)
    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)

@csrf_protect
def list_demandas(request) -> JsonResponse:
    """List all Demandas."""
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
                
                if user.role_id.role_name != 'Admin':
                    return JsonResponse({"error": "Acesso negado. Apenas Admins podem acessar demandas."}, status=403)
                
                demandas = Demanda.objects.all().order_by('-data_criacao')
                demandas_list = [
                    {
                        "id": demanda.id,
                        "disciplina": demanda.disciplina,
                        "conteudo": demanda.conteudo,
                        "professor_responsavel": demanda.professor_responsavel.full_name,
                        **({"indicacao_ativa": demanda.indicacao_ativa,
                            "fluxo": demanda.fluxo,
                            "perspectiva": demanda.perspectiva,
                            "orientacoes_pesquisa": demanda.orientacoes_pesquisa,
                            "data_criacao": demanda.data_criacao,
                            "data_resposta": demanda.data_resposta} if demanda.data_resposta else {})
                    }
                    for demanda in demandas
                ]
                return JsonResponse({"demandas": demandas_list}, status=200)
            except (InvalidToken, TokenError):
                return JsonResponse({"error": "Token inválido"}, status=401)
            except Users.DoesNotExist:
                return JsonResponse({"error": "Usuário não encontrado"}, status=404)
        else:
            return JsonResponse({"error": "Autorização não fornecida"}, status=401)
    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)

@csrf_protect
def get_demanda_response(request, demanda_id) -> JsonResponse:
    """Get the response of a Demanda."""
    if request.method == "PUT":
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                # Decodificar o token
                decoded_token = UntypedToken(token)
                user_id = decoded_token.get('user_id')
                
                # Obter o usuário a partir do ID
                user = Users.objects.get(id=user_id)
                
                if user.role_id.role_name != 'Admin':
                    return JsonResponse({"error": "Acesso negado. Apenas Admins podem responder a demandas."}, status=403)
                
                data = loads(request.body)
                demanda = Demanda.objects.get(id=demanda_id)
                demanda.fluxo = data.get("fluxo", demanda.fluxo)
                demanda.perspectiva = data.get("perspectiva", demanda.perspectiva)
                demanda.indicacao_ativa = True
                demanda.data_resposta = timezone.now()
                demanda.save()

                # Enviar email para o Professor
                professor_email = demanda.professor_responsavel.email
                email_subject = 'Resposta à Demanda'
                email_body = (
                    f'Olá, {demanda.professor_responsavel.full_name}!\n\n'
                    'Sua demanda foi respondida.\n\n'
                    f'Fluxo: {demanda.fluxo}\n'
                    f'Perspectiva: {demanda.perspectiva}\n\n'
                    'Obrigado por utilizar o sci2biz!'
                )
                send_mail(
                    email_subject,
                    email_body,
                    settings.DEFAULT_FROM_EMAIL,
                    [professor_email]
                )

                return JsonResponse({"message": "Resposta à demanda atualizada com sucesso"}, status=200)
            except (InvalidToken, TokenError):
                return JsonResponse({"error": "Token inválido"}, status=401)
            except Users.DoesNotExist:
                return JsonResponse({"error": "Usuário não encontrado"}, status=404)
            except Demanda.DoesNotExist:
                return JsonResponse({"error": "Demanda não encontrada"}, status=404)
            except (KeyError, JSONDecodeError):
                return JsonResponse({"message": "JSON inválido"}, status=400)
            except Exception as e:
                return JsonResponse({"message": str(e)}, status=400)
        else:
            return JsonResponse({"error": "Autorização não fornecida"}, status=401)


@csrf_protect
def update_demanda(request, demanda_id) -> JsonResponse:
    """Update a Demanda."""
    if request.method == "PUT":
        try:
            data = loads(request.body)
            demanda = Demanda.objects.get(id=demanda_id)

            demanda.disciplina = data.get("disciplina", demanda.disciplina)
            demanda.conteudo = data.get("conteudo", demanda.conteudo)
            demanda.indicacao_ativa = data.get("indicacao_ativa", demanda.indicacao_ativa)
            demanda.fluxo = data.get("fluxo", demanda.fluxo)
            demanda.perspectiva = data.get("perspectiva", demanda.perspectiva)
            demanda.orientacoes_pesquisa = data.get("orientacoes_pesquisa", demanda.orientacoes_pesquisa)
            demanda.data_resposta = data.get("data_resposta", demanda.data_resposta)

            demanda.save()
            return JsonResponse({"message": "Demanda atualizada com sucesso"}, status=200)

        except Demanda.DoesNotExist:
            return JsonResponse({"message": "Demanda não encontrada"}, status=404)
        except (KeyError, JSONDecodeError):
            return JsonResponse({"message": "JSON inválido"}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)

@csrf_protect
def delete_demanda(request, demanda_id) -> JsonResponse:
    """Delete a Demanda."""
    if request.method == "DELETE":
        try:
            demanda = Demanda.objects.get(id=demanda_id)
            demanda.delete()
            return JsonResponse({"message": "Demanda deletada com sucesso"}, status=200)

        except Demanda.DoesNotExist:
            return JsonResponse({"message": "Demanda não encontrada"}, status=404)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=400)

    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)

@csrf_protect
def create_turma(request) -> JsonResponse:
    """Create a new Turma."""
    if request.method == "POST":
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                # Decodificar o token
                decoded_token = UntypedToken(token)
                user_id = decoded_token.get('user_id')
                
                # Obter o usuário a partir do ID
                user = Users.objects.get(id=user_id)
                
                if user.role_id.role_name != 'Professor':
                    return JsonResponse({"error": "Acesso negado. Apenas Professores podem criar turmas."}, status=403)
                
                data = loads(request.body)
                demanda_id = data.get("demanda_id")
                nome = data.get("nome")

                if not demanda_id or not nome:
                    return JsonResponse({"message": "Campos obrigatórios faltando"}, status=400)

                demanda = Demanda.objects.get(id=demanda_id)

                turma = Turma(
                    demanda_id=demanda,
                    nome=nome,
                    professor_id=user,
                )
                turma.save()

                return JsonResponse({"message": "Turma criada com sucesso"}, status=201)

            except (InvalidToken, TokenError):
                return JsonResponse({"error": "Token inválido"}, status=401)
            except Users.DoesNotExist:
                return JsonResponse({"error": "Usuário não encontrado"}, status=404)
            except Demanda.DoesNotExist:
                return JsonResponse({"error": "Demanda não encontrada"}, status=404)
            except (KeyError, JSONDecodeError):
                return JsonResponse({"message": "JSON inválido"}, status=400)
            except Exception as e:
                return JsonResponse({"message": str(e)}, status=400)
        else:
            return JsonResponse({"error": "Autorização não fornecida"}, status=401)
    else:
        return JsonResponse({"message": "Método não permitido"}, status=405)


