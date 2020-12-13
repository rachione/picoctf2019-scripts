
from PIL import Image

img = Image.open("ctf.png")
red, green, blue = img.split()


red.save("ctfred.png")
green.save("ctfgreen.png")
blue.save("ctfrblue.png")