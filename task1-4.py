import zipfile
import os
from PIL import Image

def unzip_file(zip_file):
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall()

def get_flag(file_name):
    with open(file_name, 'r') as file:
        print(file.read())

def open_png_as_image(png_file): #get flag
    img = Image.open(png_file)
    img.show()

unzip_file("Matryoshka dolls.jpg")
open_png_as_image("flag.txt")
