"""Generate the ARCHANGEL white A multi-size Windows icon during the CI build."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).with_name("icon.ico")
size = 512
im = Image.new("RGBA", (size, size), (9, 9, 9, 255))
draw = ImageDraw.Draw(im)
font_paths = [
    r"C:\Windows\Fonts\arialbd.ttf",
    r"C:\Windows\Fonts\segoeuib.ttf",
]
font = next((ImageFont.truetype(p, 450) for p in font_paths if Path(p).exists()), None)
if font is None:
    raise RuntimeError("Windows Arial Bold or Segoe UI Bold font not found on the runner.")
bounds = draw.textbbox((0, 0), "A", font=font)
x = (size - (bounds[2] - bounds[0])) / 2 - bounds[0]
y = (size - (bounds[3] - bounds[1])) / 2 - bounds[1]
draw.text((x, y), "A", fill="white", font=font)
im.save(OUT, sizes=[(16,16), (24,24), (32,32), (48,48), (64,64), (128,128), (256,256)])
print(f"Created {OUT}")
