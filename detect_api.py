# detect_api.py
from fastapi import FastAPI, File, UploadFile
from ultralytics import YOLO
import easyocr, cv2, numpy as np, io, re
from PIL import Image
from pydantic import BaseModel

app = FastAPI()

# 初始化 YOLO 與 EasyOCR
model = YOLO("models/best.pt")

reader = easyocr.Reader(['en'])

def filter_plate_text(text: str) -> str:
    text = text.upper().replace('O','0').replace('I','1')
    filtered = re.sub(r'[^A-Z0-9]', '', text)
    if 4 <= len(filtered) <= 8:
        m = re.match(r"([A-Z]{2,3})(\d{3,4})", filtered)
        return f"{m.group(1)}-{m.group(2)}" if m else filtered
    return "N/A"

@app.post("/detect")
async def detect(file: UploadFile = File(...)):
    data = await file.read()
    img = Image.open(io.BytesIO(data)).convert("RGB")
    img = np.array(img)

    results = model.predict(img, save=False)
    boxes = results[0].boxes.xyxy.cpu().numpy()

    plate = "N/A"
    if len(boxes)>0:
        x1,y1,x2,y2 = map(int, boxes[0])
        plate_img = img[y1:y2, x1:x2]
        gray = cv2.cvtColor(plate_img, cv2.COLOR_RGB2GRAY)
        enhanced = cv2.adaptiveThreshold(gray,255,
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY_INV,25,15)
        result = reader.readtext(enhanced, allowlist='ABCDEFGHJKLMNPQRSTUVWXYZ0123456789')
        if result:
            result.sort(key=lambda x: -x[2])
            plate = filter_plate_text(result[0][1])

    return {"plate_text": plate}
