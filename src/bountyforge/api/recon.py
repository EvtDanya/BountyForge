import fastapi
from app.modules.recon import ReconModule

app = fastapi.FastAPI()


@app.post("/subdomains")
async def recon(target: str):
    recon = ReconModule(target)
    subdomains = recon.run_subfinder()
    return {"subdomains": subdomains}
