# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.


def login(resquest):
	t= 'login.html'
	if resquest.method == 'GET':
		return render(resquest, t, {'errores' :'todo bien'})
	else:
		return render(resquest, t,{'errores' : 'muchos intentos'} )