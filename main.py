from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import os

# 初始化FastAPI应用
app = FastAPI(title="电力负荷计算工具")

# 创建静态文件和模板目录
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)

# 挂载静态文件目录
app.mount("/static", StaticFiles(directory="static"), name="static")

# 配置模板目录
templates = Jinja2Templates(directory="templates")

def calculate_pjs(pe, kx):
    """计算有功功率Pjs"""
    return round(pe * kx, 2)

def calculate_ljs(pjs, cos_phi):
    """计算电流Ijs（三相380V）"""
    pjs_w = pjs * 1000  # 转换为瓦特
    ljs = pjs_w / (1.732 * 380 * cos_phi)
    return round(ljs, 2)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """显示首页表单"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/calculate", response_class=HTMLResponse)
async def calculate(
    request: Request,
    pe: float = Form(...),
    kx: float = Form(...),
    cos: float = Form(...)
):
    """处理计算请求并返回结果"""
    pjs = calculate_pjs(pe, kx)
    ljs = calculate_ljs(pjs, cos)
    
    return templates.TemplateResponse(
        "index.html", 
        {
            "request": request,
            "pe": pe,
            "kx": kx,
            "cos": cos,
            "pjs": pjs,
            "ljs": ljs
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    