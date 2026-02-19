import os


class Config:
    N8N_WEBHOOK_URL = os.getenv(
        "N8N_WEBHOOK_URL",
        "https://n8n.shravanpandala.me/webhook/scan",
    )
    N8N_TIMEOUT_SECONDS = float(os.getenv("N8N_TIMEOUT_SECONDS", "20"))
