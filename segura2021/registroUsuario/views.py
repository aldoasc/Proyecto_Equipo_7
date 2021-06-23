from __future__ import unicode_literals
from registroUsuario import models
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render,redirect
from django.conf import settings
from django.template import Template,Context
from django.core.files.storage import FileSystemStorage
import os
import base64
import hashlib
import datetime
from datetime import timezone
from registroUsuario.decoradores import login_requerido

#---------------Para cifrado AES------------------------#
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#--------------------Llaves-----------------------#
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Create your views here.
def registroUsuario(request):
    if request.method == 'GET':
        template='registroUsuario.html'
        contador = request.session.get('contador', 0)
        contexto = {'contador' : contador}
        request.session['contador'] = contador + 1
        respuesta = render(request,template,contexto)
        respuesta.set_cookie('contador2', contador, max_age=None, samesite='Strict', secure=True, httponly=True)
        return render(request,template)
    elif request.method == 'POST':
        nombre_completo = request.POST.get('nombre','').strip()
        nick = request.POST.get('nickname','').strip()
        correo_electronico = request.POST.get('correo','').strip()
        password = request.POST.get('contraseña','').strip()

    usuario = models.Usuario()
    #generar llave privada
    private_key=generar_llave_privada()
    #convertir de objeto python a PEM
    pem_private=convertir_llave_privada_a_PEM(private_key)
    #generar iv
    vector_inicializacion=generar_iv()
    #codificar iv a texto plano
    texto_iv=generar_bytes_a_texto(vector_inicializacion)
    #guardar iv en base de datos
    usuario.Iv=texto_iv
    #generacion de llave aes del password
    llave_aes=generar_llave_aes_from_password(password)
    #cifrar llave privada
    llave_privada_cifrada=cifrar(pem_private,llave_aes,vector_inicializacion)
    #decodificar a texto plano llave cifrada
    llave_privada_cifrada_texto=generar_bytes_a_texto(llave_privada_cifrada)
    #poner en la base de datos la llave privada cifrada en texto
    usuario.Llave_privada=llave_privada_cifrada_texto
    #hash del password
    hash_password_user=generar_hash_password(password)
    #ingresarlo a la base de datos
    usuario.Password=hash_password_user
    #generacion de llave publica a partir de la privada
    public_key=generar_llave_publica(private_key)
    #pem para llave publica
    pem_public=convertir_llave_publica_bytes(public_key)
    #decofificacion de llave publica base64
    llave_publica_texto=generar_bytes_a_texto(pem_public)
    #ingresarla a la base
    usuario.Llave_publica=pem_public






    usuario.Nombre_Completo = nombre_completo
    usuario.Nick = nick
    usuario.Correo_electronico = correo_electronico

    usuario.save()
    return redirect('/login')

#Llaves

def generar_llave_privada():
	private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
	return private_key

def generar_llave_publica(llave_privada):
	return llave_privada.public_key()

#bytes a PEM
def convertir_llave_privada_a_PEM(llave_privada):
	pem_private = llave_privada.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption())
	return pem_private

#pem a Bytes
def convertir_bytes_llave_privada(llave_privada_pem):
	resultado = serialization.load_pem_private_key(llave_privada_pem,backend=default_backend(),password=None)
	return resultado

#bytes a pem
def convertir_llave_publica_bytes(llave_publica):
	resultado = llave_publica.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
	return resultado

#pem a bytes
def convertir_llave_publica_pem_a_bytes(contenido_pem):
	resultado = serialization.load_pem_public_key(contenido_pem,backend=default_backend())
	return resultado


#PASSWORD HASHING#

def generar_llave_aes_from_password(password):
	password = password.encode('utf-8')
	derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data ',backend=default_backend()).derive(password)
	return derived_key

def cifrar(llave_pem, llave_aes, iv):
	aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),backend=default_backend())
	cifrador = aesCipher.encryptor()
	cifrado = cifrador.update(llave_pem)
	cifrador.finalize()
	return cifrado

def descifrar(cifrado, llave_aes, iv):
	aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),backend=default_backend())
	descifrador = aesCipher.decryptor()
	plano = descifrador.update(cifrado)
	descifrador.finalize()
	return plano

def generar_iv():
	iv=os.urandom(16)
	return iv

def generar_hash_password(password_usuario):
    hasher = hashlib.sha512()
    hasher.update(password_usuario.encode('utf-8'))
    return hasher.hexdigest()

def generar_bytes_a_texto(contenido_cifrado_bytes):
    texto=base64.b64encode(contenido_cifrado_bytes)
    texto=texto.decode('utf-8')
    return texto

def generar_texto_a_bytes(contenido_cifrado_texto):
    texto=base64.b64decode(contenido_cifrado_texto)
    return texto



#credenciales

def registraCredencial(request):
    template = 'registraCredencial.html'
    if request.method == 'GET':
        return render(request,template)
    elif request.method == 'POST':
        Sitio = request.POST.get('sitio', '').strip()
        Usuario = request.POST.get('usuario', '').strip()
        Contraseña = request.POST.get('contraseña', '').strip()

        iv = os.urandom(16)
        llave_aes = generar_llave_aes_from_password(Contraseña)
        Contraseña = bytes(Contraseña, 'utf-8')
        contraseña_cifrada = cifrar(Contraseña, llave_aes, iv)
        Contraseña = generar_bytes_a_texto(contraseña_cifrada)
        iv = generar_bytes_a_texto(iv)

        credencial = models.Credencial()
        credencial.sitio = Sitio
        credencial.usuario = Usuario
        credencial.iv = iv
        credencial.contraseña = Contraseña



        credencial.save()
        return redirect('/home')








#logout para tiempo de sesion
def logout(request):
	request.session.flush()
	respuesta=redirect('registroUsuario')
	return respuesta


def index(request):
	template='index.html'
	return render(request,template)

def home(request):
	template='home.html'
	return render(request,template)

def visualizar(request):
	template='visualizar.html'
	return render(request,template)

def credencial(request):
	template='registraCredencial.html'
	return render(request,template)

def login(request):
	template = 'login.html'
	ingreso = request.session.get('ingreso',False)
	if request.method == 'GET':
		if ingreso:
			return redirect('home/')
		return render(request,template)
	elif request.method == 'POST':
		nickname = request.POST.get('nickname','').strip()
		password = request.POST.get('contraseña','').strip()
		try:
			hash_password = generar_hash_password(password)
			models.Usuario.objects.get(Nick=nickname,Password=hash_password)
			request.session['ingreso'] = True
			request.session['nombre'] = nickname
			return redirect('home/')
		except:
			errores = ['usuario o contraseña incorrecta']
			return render(request,template,{'errores': errores})

#logout para cerrar la sesion
def logOut(request):
    request.session.flush()
    return redirect('/login')



def password_correcto(password):
    errores_password = []
    if '' in password:
        errores_password.append('La contraseña no puede tener espacios')
    if not any(character.isupper() for caracter in password):
        errores_password.append('La contraseña requiere almenos una Mayuscula')
    if not any(character.isdigit() for caracter in password):
        errores_password.append('La contraseña debe tener almenos 1 numero')
    if len(password) < 10:
        errores_password.append('La contraseña debe tener almenos 10 caracteres')
    return errores_password

def nick_duplicado(usuario):
    nick = models.Usuario.objects.filter(nick=usuarios.nick)
    if len(nick) > 0:
        return True
    return False

@login_requerido
def algo(request):
    return(request)