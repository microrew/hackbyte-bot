from PIL import Image
import imagehash
import os
import json

hashes = []

for file in os.listdir("scam_images"):
    img = Image.open("scam_images/" + file)
    hashes.append(str(imagehash.phash(img)))

with open("known_scam_hashes.json", "w") as f:
    json.dump(hashes, f, indent=2)

print("Done")