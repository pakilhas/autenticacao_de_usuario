from django.shortcuts import render
from django.urls import path
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from django.shortcuts import render, redirect, get_object_or_404


def home (request):
    return render(request, 'home.html')
def footer (request):
    return render(request, 'footer.html')



def sigup(request):
    error = None
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            username = form.cleaned_data.get('username')
            password1 = form.cleaned_data.get('password1')
            password2 = form.cleaned_data.get('password2')

            if password1 != password2:
                error = 'As senhas não correspondem.'
            elif User.objects.filter(email=email).exists():
                error = 'Este e-mail já está em uso.'
            elif User.objects.filter(username=username).exists():
                error = 'Este nome de usuário já está em uso.'
            else:
                user = form.save(commit=False)  # Salvando o usuário 
                user.set_password(password1)  # Define a senha
                user.save()  # Salva o usuário
                login(request, user)  # Efetua login do usuário criado
                return redirect('task')
        else:
            error = 'Formulário inválido. Por favor, verifique os dados inseridos:'
            for field, errors in form.errors.items():
                error += f'\n{field}: {", ".join(errors)}'
    else:
        form = UserCreationForm()
    
    return render(request, 'sigup.html', {'form': form, 'error': error})

from django.contrib.auth import authenticate

def login_user(request):
    if request.method == 'GET':
        return render(request, 'login.html', {'form': AuthenticationForm()})
    elif request.method == 'POST':
        form = AuthenticationForm(request, request.POST)  # Crie uma instância do formulário de autenticação
        if form.is_valid():
            username = form.cleaned_data.get('username')  # Obtenha o nome de usuário do formulário
            password = form.cleaned_data.get('password')  # Obtenha a senha do formulário
            user = authenticate(request, username=username, password=password)  # Autenticar com nome de usuário e senha
            if user is not None:
                login(request, user)
                return redirect('home')  # Redirecionar para a página home após o login
            else:
                return render(request, 'login.html', {'form': form, 'error': 'Usuário ou senha incorretos'})
        else:
            return render(request, 'login.html', {'form': form, 'error': 'Por favor, digite o nome de usuário e a senha'})







def sair (request):
    logout (request)
    return redirect ('home')

def task (request):
    return render(request, 'task.html')

