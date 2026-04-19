
if __name__ == "__main__":
    # Ejecutar en Python para crear la estructura de evidencias
    import os
    carpetas = [
        'evidencias_usb/documentos',
        'evidencias_usb/imagenes',
        'evidencias_usb/logs',
    ]
    archivos = [
        ('evidencias_usb/documentos/contrato.docx', 'Datos confidenciales del contrato'),
        ('evidencias_usb/documentos/notas.txt',     'Notas personales sospechosas'),
        ('evidencias_usb/imagenes/foto1.jpg',       ''),
        ('evidencias_usb/imagenes/captura.png',     ''),
        ('evidencias_usb/logs/sistema.log',         '2024-03-15 08:17:01 WARN Conexion'),
    ]

    for c in carpetas:
        os.makedirs(c, exist_ok=True)

    for ruta, contenido in archivos:
        with open(ruta, 'w') as f:
            f.write(contenido)

    print('[+] Dataset creado en evidencias_usb/')
