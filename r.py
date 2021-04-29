import logging
logging.basicConfig(level=logging.DEBUG)   #librerias de logs

def introducir_nombre():
    while True:
        nombre = input("escriba su nombre: ")
        try:
            nombre = str(nombre)
            return nombre
        except ValueError:
            print ("tu nombre no debe contener numeros")
        
def introducir_curp():
    while True:
        nombre = input("escriba su nombre: ")
        try:
            nombre = str(nombre)
            return nombre
        except ValueError:
            print ("tu nombre no debe contener numeros")

introducir_nombre()