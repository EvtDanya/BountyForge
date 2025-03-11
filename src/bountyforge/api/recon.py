import fastapi
from app.modules.recon import ReconModule

app = fastapi.FastAPI()


@app.post("/subdomains")
async def recon(target: str):
    recon = ReconModule(target)
    subdomains = recon.run_subfinder()
    return {"subdomains": subdomains}

from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import make_scorer

# Создание стратифицированных фолдов для кросс-валидации
cv = StratifiedKFold(n_splits=5)

# Определение метрики для использования в кросс-валидации
scorer = make_scorer(f1_score)

# Применение кросс-валидации
cv_scores = cross_val_score(model, X, y, cv=cv, scoring=scorer)