from data_layer.data_layer import DataLayer
from cryptography.fernet import Fernet
import os

class BusinessLayer:
    def _init_(self):
        self.data_layer = DataLayer()
        self.clave = self.obtener_clave()

    def obtener_clave(self):
        if os.path.exists('clave.key'):
            with open('clave.key', 'rb') as file:
                clave = file.read()
        else:
            clave = Fernet.generate_key()
            with open('clave.key', 'wb') as file:
                file.write(clave)
        return clave

    def encriptar(self, contrasena):
        f = Fernet(self.clave)
        return f.encrypt(contrasena.encode())

    def desencriptar(self, contrasena_encriptada):
        f = Fernet(self.clave)
        return f.decrypt(contrasena_encriptada).decode()

    def agregar_contrasena(self, sitio_web, nombre_usuario, contrasena):
        contrasena_encriptada = self.encriptar(contrasena)
        self.data_layer.agregar_contrasena(sitio_web, nombre_usuario, contrasena_encriptada)

    def obtener_contrasenas(self):
        registros = self.data_layer.obtener_contrasenas()
        contrasenas = []
        for registro in registros:
            id, sitio_web, nombre_usuario, contrasena_encriptada = registro
            contrasena = self.desencriptar(contrasena_encriptada)
            contrasenas.append({
                'Id': id,
                'SitioWeb': sitio_web,
                'NombreUsuario': nombre_usuario,
                'Contrasena': contrasena
            })
        return contrasenas

    def actualizar_contrasena(self, id_contrasena, sitio_web, nombre_usuario, contrasena):
        contrasena_encriptada = self.encriptar(contrasena)
        self.data_layer.actualizar_contrasena(id_contrasena, sitio_web, nombre_usuario, contrasena_encriptada)

    def eliminar_contrasena(self, id_contrasena):
        self.data_layer.eliminar_contrasena(id_contrasena)