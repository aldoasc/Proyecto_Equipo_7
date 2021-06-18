# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.

class Usuario(models.Model):
	Nombre_Completo=models.CharField(max_length=100)
	Nick=models.CharField(max_length=20)
	Correo_electronico=models.EmailField()
	Password=models.CharField(max_length=1024)
