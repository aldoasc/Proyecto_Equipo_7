# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.

class registroUsuario(models.Model):
		nombre=models.CharField(max_length=30)
		contra=models.CharField(max_length=30)