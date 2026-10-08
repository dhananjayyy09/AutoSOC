from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.lifespan import lifespan
from app.core.exceptions import global_exception_handler
from app.api.health import router as health_router

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.PROJECT_NAME,
        description="Explainable Multi-Agent AI Platform for Autonomous Security Operations",
        version=settings.VERSION,
        lifespan=lifespan
    )

    # CORS config
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global Exception Handler
    app.add_exception_handler(Exception, global_exception_handler)

    # Include routers
    app.include_router(health_router, tags=["Health"])

    return app

app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
