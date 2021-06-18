# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from registroUsuario import models
from django.shortcuts import render
from django.shortcuts import render,redirect
import datetime
from datetime import timezone

# Create your views here.
def registroUsuario(request):
    if request.method== 'GET':
        template='registroUsuario.html'
        contador = request.session.get('contador', 0)
        contexto = {'contador' : contador}
        request.session['contador'] = contador + 1
        respuesta = render(request,template,contexto)
        respuesta.set_cookie('contador2', contador, max_age=None, samesite='Strict', secure=True, httponly=True)
        return render(request,template)
    elif request.method=='POST':
        nombre_completo=request.POST.get('nombre','').strip()
        nick=request.POST.get('nickname','').strip()
        correo_electronico=request.POST.get('correo','').strip()
        password=request.POST.get('contraseña','').strip()

    usuario=models.Usuario()

    usuario.Nombre_Completo=nombre_completo
    usuario.Nick=nick
    usuario.Correo_Electronico=correo_electronico
    usuario.save()

    return redirect('/login')

def logout(request):
	request.session.flush()
	respuesta=redirect('registroUsuario')
	return respuesta


def index(request):
	template='index.html'
	return render(request,template)

#def home(request):
#	template='home.html'
#	return render(request,template)

#def visualizar(request):
#	template='visualizar.html'
#	return render(request,template)

def login(request):
	template='login.html'
	ingreso=request.session.get('ingreso',False)
	if request.method=='GET':
		if ingreso:
			return redirect('usuario/')
		return render(request,template)
	elif request.method=='POST':
		nickname=request.POST.get('nickname','').strip()
		password=request.POST.get('contraseña','').strip()
		try:
			models.Usuario.objects.get(Nick=nickname,Password=password)
			request.session['ingreso']=True
			request.session['nombre']=nickname
			return redirect('usuario/')
		except:
			errores={'usuario o contraseña incorrecta'}
			return render(request,template,{'errores': errores})