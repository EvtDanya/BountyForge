from fastapi import APIRouter
from bountyforge.modules import reconnaissance, scanner_web, attack

router = APIRouter()


@router.post("/simulate")
async def simulate_attack(target: str):
    """
    Эндпоинт для симуляции веб-атаки.
    Принимает целевой домен (например, example.com) и возвращает:
      - данные разведки
      - результаты веб-сканирования
      - сгенерированный сценарий атаки (имитация вызова LLM)
    """
    # Сбор информации о цели (разведка)
    recon_results = reconnaissance.run(target)

    # Выполнение веб-сканирования (например, проверка базового HTTP-запроса)
    web_scan_results = scanner_web.run_scan(target)

    # Генерация сценария атаки (имитация работы LLM)
    attack_scenario = attack.generate_scenario(recon_results)

    return {
        "target": target,
        "recon": recon_results,
        "web_scan": web_scan_results,
        "attack_scenario": attack_scenario
    }
