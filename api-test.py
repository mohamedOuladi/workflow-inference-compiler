# Python core libraries
import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from auth.auth import authenticate
from auth.settings import SETTINGS

# LOCK = asyncio.Lock()

# set_lock(LOCK)


"""
API Setup
"""


app = FastAPI(
    title="Plots API",
    description="API for processing tabular data for visualization.",
)

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

"""
MetaData endpoints
"""


@app.get(
    "/",
    status_code=status.HTTP_200_OK
)
@authenticate
async def collections_endpoint(request: Request) -> None:
    """Get a list of available data collections.

    Returns:
        A list of data collections(folders, databases, etc...)
    """
    #collections = await list_collections(SETTINGS.DATA_PATH)
    print("hello world!")
    print(request)
    return None


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="127.0.0.1", port=5000, log_level="info")