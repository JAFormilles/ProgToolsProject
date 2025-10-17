
from typing import Union
from fastapi import FastAPI, HTTPException

app = FastAPI()

items = []

@app.post("/items")
def create_item(item: str):
    items.append(item)
    return items

@app.get("/items/{item_id}")
def get_item(item_id: int) -> str:
    if item_id < len(items):
        return items[item_id]
    else:
        raise HTTPException(status_code = 404, detail=f"Item '{item_id}' not Found")

@app.get("/items")
def get_items():
    return items






