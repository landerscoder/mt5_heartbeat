from typing import List, Optional, Tuple
from nicegui import ui, Tailwind, Client
from fastapi import Form,Depends,FastAPI
from fastapi.responses import RedirectResponse
from ex4nicegui.reactive import rxui
from pydantic import BaseModel
from ex4nicegui import to_ref, ref_computed, effect, effect_refreshable
from niceguiToolkit.layout import inject_layout_tool
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime
from fastapi.security import OAuth2PasswordRequestForm
from uuid import uuid4
import json
import threading
import time
from urllib import parse
import requests
from app.db import User, create_db_and_tables
from app.schemas import UserCreate, UserRead, UserUpdate
from app.users import auth_backend, current_active_user, fastapi_users, get_async_session, get_user_db, get_user_manager, get_jwt_strategy
import contextlib
import uvicorn

token ="7396762086:AAGHhqVLVTOrH9gUVSSa3RcVuBLOEYKMBX8" #"6081891861:AAHJZFPRiiUcaTff4NZXcmDDguzPBPWwGjM"
chat_id ="-1002153308557" #"-1002025253399"  #频道id 835664676
checktime =3 #3分钟
dsicord_webhook_url="https://discord.com/api/webhooks/1277707804823523399/iC0OR_d3C5UypnYIluvT66Is1N6oJHFVf5eoQOZDob6-g-iGh5XWGSVkJJ70DcFmVGd_"

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await create_db_and_tables()
    yield
    # Shutdown
    # Add any cleanup code here if needed

app = FastAPI(lifespan=lifespan)

# Remove the @app.on_event("startup") decorator and its function

app.include_router(
    fastapi_users.get_auth_router(auth_backend), prefix="/auth/jwt", tags=["auth"]
)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_verify_router(UserRead),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/users",
    tags=["users"],
)

@app.get("/authenticated-route")
async def authenticated_route(user: User = Depends(current_active_user)):
    return {"message": f"Hello {user.email}!"}


@ui.page('/', dependencies=[Depends(current_active_user )])
async def main(client: Client):
  input_search = rxui.input(
      "Account Search",
      value=r_input,
  ).style("align-self:flex-start;font-size:1rem").props(
      'outlined clearable debounce="500"')
  
  table = rxui.table(columns=columns, rows=rows, row_key='id',
                     pagination=15).style("height:auto;width:100%")

  table.add_slot(
      'body-cell-lived', '''
        <q-td key="lived" :props="props">
            <q-badge :color="props.value ? 'green' : 'red'">
                {{ props.value }}
            </q-badge>
        </q-td>
    ''')

#inject_layout_tool()

#region 数据
columns = [
    {
        'name': 'name',
        'label': 'Name',
        'field': 'name',
        'required': True,
        'align': 'left'
    },
    {
        'name': 'id',
        'label': 'Account',
        'field': 'id',
        'sortable': True,
        'align': 'left'
    },
    {
        'name': 'lived',
        'label': 'Lived',
        'field': 'lived',
        'sortable': True,
        'align': 'left'
    },
    {
        'name': 'updatetime',
        'label': 'Update',
        'field': 'updatetime',
        'sortable': True
    },
]
rows = []

r_input = to_ref("")


@ref_computed
def cp_account_names():
  return [name for name in rows if name.find(r_input.value) >= 0]


#temp
@ref_computed
def cp_data():
  return [row for row in rows if row['name'].find(r_input.value) >= 0]


#endregion


class Item(BaseModel):
  id: str
  name: str = None
  lasttime: Optional[int] = None
  lived: Optional[bool] = True

get_async_session_context = contextlib.asynccontextmanager(get_async_session)
get_user_db_context = contextlib.asynccontextmanager(get_user_db)
get_user_manager_context = contextlib.asynccontextmanager(get_user_manager)

def user_logout() -> None:
    app.storage.user.clear()
    ui.open('/login')

async def user_authenticate(email: str, password: str) -> Optional[User]:
    try:
        async with get_async_session_context() as session:
            async with get_user_db_context(session) as user_db:
                async with get_user_manager_context(user_db) as user_manager:
                    user_logout()
                    credentials = OAuth2PasswordRequestForm(username=email, password=password) 
                    user = await user_manager.authenticate(credentials)
                    if user is None or not user.is_active:
                        return None
                    return user
    except:
        return None

async def user_create_token(user: User) -> Optional[str]:
    try:
        async with get_async_session_context() as session:
            async with get_user_db_context(session) as user_db:
                async with get_user_manager_context(user_db) as user_manager:
                    if user is None:
                        return None
                    strategy = get_jwt_strategy()
                    token = await strategy.write_token(user)
                    if token is not None:
                        return token
                    else:
                        return None
    except:
        return None    

async def user_check_token(token: str) -> bool:
    try:
        async with get_async_session_context() as session:
            async with get_user_db_context(session) as user_db:
                async with get_user_manager_context(user_db) as user_manager:
                    if token is None:
                        return False
                    strategy = get_jwt_strategy()
                    user = await strategy.read_token(token, user_manager)
                    if user is None or not user.is_active:
                        return False
                    else:
                        return True
    except:
        return False
unrestricted_page_routes = {'/login','/pin'}
class AuthMiddleware(BaseHTTPMiddleware):
  async def dispatch(self, request, call_next):
      if not request.url.path.startswith('/_nicegui') and request.url.path not in unrestricted_page_routes:
          return RedirectResponse('/login')
      return await call_next(request)

app.add_middleware(AuthMiddleware)

@ui.page('/login')
async def login_page() -> Optional[RedirectResponse]:
    async def try_login():
        user = await user_authenticate(email=email.value, password=password.value)
        token = await user_create_token(user)
        if token is not None:
            app.storage.user.update({'username': email.value, 'authenticated': True,'auth_token': token})
            ui.navigate.to(app.storage.user.get('referrer_path', '/'))  # go back to where the user wanted to go
        else:
            ui.notify('email or password wrong!', color='negative')

    if await user_check_token(app.storage.user.get('auth_token', None)):
        return RedirectResponse('/')
          
    with ui.card().classes('absolute-center'):
        email = ui.input('email').on('keydown.enter', try_login)
        password = ui.input('password', password=True, password_toggle_button=True).on('keydown.enter', try_login)
        ui.button('Login', on_click=try_login) 

@app.get("/items")
async def read_items():
  return [row for row in rows]


@app.post("/pin")
async def pin(text=Form(...)):
  """
    pin information:

    - **id**: account id
    - **name**: account name
    - **lasttime**: last time
    - **lived**: account is lived
    """
  item = json.loads(text)
  DeleteRow(item)
  item["key"] =item["id"]+item["name"]
  item["lasttime"] = datetime.now().timestamp()
  item["updatetime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  item["lived"] = True
  item["count"] = 0
  rows.append(item)
  return item


def DeleteRow(item):
  for row in rows:
    if row['key'] == item["id"]+item["name"]:
      rows.remove(row)
      return
  accountname = item["name"]
  SendMessage(f"Account:{accountname} is online")


#lock = threading.Lock()

def sendDiscord(message):

  # Your webhook URL
  #dsicord_webhook_url = 'YOUR_WEBHOOK_URL_HERE'

  # The message you want to send
  data = {
  "content": "Hello from Python via Webhook!"
  }

  # Post the message to the webhook
  response = requests.post(dsicord_webhook_url, json=data)

  # Check if the request was successful
  if response.status_code == 204:
    print("Message sent successfully!")
  else:
    print(f"Failed to send message. Status code: {response.status_code}, response: {response.text}")
 
def SendMessage(message):
  send_message = parse.quote(message)
  url=f"https://eovjbxgqbz3mq85.m.pipedream.net?text={send_message}"
  #url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&text={send_message}"
  requests.post(url)


def checklived():
  for row in rows:
    if row['lasttime'] + 60 * checktime < datetime.now().timestamp():
      row['lived'] = False
      row['count'] = row['count'] + 1
      SendMessage(f"Account:{row['name']} is offline")
      if row['count'] > 3:
        rows.remove(row)
  print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), len(rows))
  create_timer()


def create_timer():
  t = threading.Timer(60, checklived)
  t.start()
  t.join()

ui.run_with(app)

uvicorn.run(app, host='0.0.0.0', port=80,ssl_keyfile="./key.pem", ssl_certfile="./cert.pem")

#ui.run(host="0.0.0.0",port=80,reload=True,storage_secret="none")
threading.Thread(target=create_timer).start()

