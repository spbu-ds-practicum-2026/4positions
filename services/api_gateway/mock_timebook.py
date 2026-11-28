"""Тестовая заглушка HTTP-контракта; не реализует настоящие бронирования."""
from typing import Annotated
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(title='TimeBook MOCK — not real bookings')

class BookingRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    res_id: Annotated[int, Field(gt=0)]
    usr_id: Annotated[int, Field(gt=0)]
    request_id: str

class CancelRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    resource_id: Annotated[int, Field(gt=0)]
    request_id: str

@app.get('/resources')
def resources():
    return {'items': [{'res_id': 7, 'date': '2026-12-01', 'time': '10:00-11:00'},
                      {'res_id': 8, 'date': '2026-12-01', 'time': '11:00-12:00'}], 'partial': False}

@app.post('/booking', status_code=201)
def book(body: BookingRequest, x_user_id: int = Header(gt=0)):
    if body.usr_id != x_user_id:
        raise HTTPException(403, detail='booking_not_owned')
    if body.res_id not in (7, 8):
        raise HTTPException(404, detail='resource_not_found')
    return {'booking_id': 42, 'status': 'confirmed'}

@app.post('/booking/{booking_id}/cancel')
def cancel(booking_id: int, body: CancelRequest, x_user_id: int = Header(gt=0)):
    return {'booking_id': booking_id, 'resource_id': body.resource_id, 'status': 'cancelled'}

if __name__ == '__main__':
    import argparse
    import uvicorn
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8001)
    args = parser.parse_args()
    uvicorn.run(app, host='127.0.0.1', port=args.port)
