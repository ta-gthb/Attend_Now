# face_utils.py
import face_recognition
import numpy as np
import os
# face_utils.py

import face_recognition

def encode_face(image_path):
    image = face_recognition.load_image_file(image_path)
    encodings = face_recognition.face_encodings(image)
    if encodings:
        return encodings[0]
    return None

def compare_faces(known_encoding, unknown_encoding, tolerance=0.5):
    results = face_recognition.compare_faces([known_encoding], unknown_encoding, tolerance=tolerance)
    return results[0]

def encode_image(image_path):
    image = face_recognition.load_image_file(image_path)
    encodings = face_recognition.face_encodings(image)
    if encodings:
        return encodings[0]  # return first face encoding
    return None

def match_face(known_encoding, unknown_encoding):
    results = face_recognition.compare_faces([known_encoding], unknown_encoding)
    return results[0]
