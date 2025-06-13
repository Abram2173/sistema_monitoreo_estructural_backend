from google.cloud import vision
import os
import tempfile
import requests

def analyze_image(image_content):
    """Analiza una imagen con Google Cloud Vision y detecta grietas o daños."""
    try:
        # Inicializar el cliente de Vision (asumimos que se configura en main.py)
        client = vision.ImageAnnotatorClient()
        image = vision.Image(content=image_content)
        response = client.label_detection(image=image)
        labels = [label.description.lower() for label in response.label_annotations]
        print(f"Etiquetas detectadas: {labels}")

        # Detectar riesgos (grietas, daños, deformaciones)
        has_crack = any(keyword in labels for keyword in ["crack", "damage", "fracture", "deformation"])
        evaluation = "Análisis preliminar: " + ("posible grieta o daño detectado" if has_crack else "ningún daño evidente detectado")

        return {"evaluation": evaluation, "has_crack": has_crack}
    except Exception as e:
        print(f"Error en el análisis de la imagen: {str(e)}")
        raise Exception(f"Error al procesar la imagen con Vision API: {str(e)}")

def get_image_content_from_url(url, headers):
    """Descarga el contenido de una imagen desde una URL y lo guarda temporalmente."""
    try:
        response = requests.get(url, headers=headers, timeout=10, stream=True)
        if response.status_code != 200:
            print(f"Error al descargar URL: {response.status_code}, {response.text}")
            raise Exception(f"URL de imagen no accesible: {response.status_code}")
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as temp_file:
            for chunk in response.iter_content(chunk_size=8192):
                temp_file.write(chunk)
            temp_file_path = temp_file.name
        
        with open(temp_file_path, 'rb') as f:
            image_content = f.read()
        print(f"Descargada y guardada temporalmente: {temp_file_path}, tamaño: {len(image_content)} bytes")
        
        # Eliminar el archivo temporal
        os.unlink(temp_file_path)
        return image_content
    except requests.exceptions.RequestException as e:
        print(f"Excepción al descargar URL: {str(e)}")
        raise Exception(f"Error al descargar la URL: {str(e)}")