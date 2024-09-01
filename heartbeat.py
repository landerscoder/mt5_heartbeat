from typing import List, Optional, Tuple
from nicegui import ui, Tailwind, Client,app,events # Add this import at the top of your file
from nicegui.storage import Storage
from fastapi import Form,Depends,FastAPI,Request, HTTPException
from fastapi.responses import RedirectResponse
from ex4nicegui.reactive import rxui
from pydantic import BaseModel
from ex4nicegui import to_ref, ref_computed,deep_ref,on,to_raw
from niceguiToolkit.layout import inject_layout_tool
from starlette.middleware.base import BaseHTTPMiddleware
from datetime import datetime
from fastapi.security import OAuth2PasswordRequestForm
from uuid import uuid4, UUID  # Add UUID to the import statement
import json
import threading
import time
from urllib import parse
import contextlib
from app.db import User, create_db_and_tables
from app.schemas import UserCreate, UserRead, UserUpdate
from app.users import auth_backend, current_active_user, fastapi_users,get_all_user_manager, get_async_session, get_user_db, get_user_manager, get_jwt_strategy,get_all_user_db,BaseUserDatabase
import requests
from sqlalchemy import select
import uvicorn

token ="7396762086:AAGHhqVLVTOrH9gUVSSa3RcVuBLOEYKMBX8" #"6081891861:AAHJZFPRiiUcaTff4NZXcmDDguzPBPWwGjM"
chat_id ="-1002153308557" #"-1002025253399"  #频道id 835664676
checktime =60*5 #3
dsicord_webhook_url="https://discord.com/api/webhooks/1277707804823523399/iC0OR_d3C5UypnYIluvT66Is1N6oJHFVf5eoQOZDob6-g-iGh5XWGSVkJJ70DcFmVGd_"

async def lifespan():
    # Startup
    await create_db_and_tables()

app.on_startup(lifespan)


#app = FastAPI(lifespan=lifespan)

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
        'name': 'equity',
        'label': 'Equity',
        'field': 'equity',
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
rows = deep_ref([])
user_row=deep_ref([])
r_input = to_ref("")

@ui.page('/')
async def main(user: User = Depends(current_active_user)):
  with rxui.row().classes("w_full"):
    if user.is_superuser:
        input_search = rxui.input(
            "Account Search"
        ).style("align-self:flex-start;font-size:1rem").props(
      'outlined clearable debounce="500"')
    else:
        r_input.value=user.email
        rxui.label("Users:"+r_input.value).style("align-self:flex-end;font-size:1rem")
    async def create_pwd_ui():
        with ui.dialog() as dialog, ui.card():
            async def on_change_pwd():
                await change_pwd(user.id,password.value,user.email,user.is_superuser) 
                dialog.close()
            password=ui.input("Password",password=True,password_toggle_button=True
              ).style("align-self:flex-start;font-size:1rem").props(
               'outlined debounce="500" type="password"')
            with ui.row():
                ui.button('Confirm', on_click=on_change_pwd)
           
        dialog.open()
    rxui.button("change pwd",on_click=create_pwd_ui).style("align-self:flex-end")
    
    
    async def change_pwd(uid,password,email,issuperuser):
        scripts=f'''
                fetch('/users/{uid}', {{
                    method: 'PATCH',
                    headers: {{'Content-Type': 'application/json'}}, 
                    body: JSON.stringify({{"password": "{password}","email": "{email}","is_active": true,"is_superuser": {'true' if issuperuser==True else 'false'},"is_verified": false}})
                }}).then(response => {{
                    if (!response.ok) {{  
                        return response.text().then(text => {{ 
                            throw new Error(text);  
                        }});
                    }}
                    return "Ok"
                }}).catch(error => {{
                    console.error('There was a problem with the fetch operation:', error); 
                    return "Failed"
                }})

            '''
        print(scripts)
        result=await ui.run_javascript(scripts,timeout=10)
        ui.notify(result)
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
  r_input.value=user.email

  if user.is_superuser:
     table.bind_rows(rows)
  else:
     table.bind_rows(user_row)
@ref_computed
def cp_account_names():
  #r_input.value = r_input.value or ''
  return [name for name in rows.value if name.find(r_input.value) >= 0]

@on(rows,r_input)
def user_row_watch():
  user_row.value=[row for row in to_raw(rows.value) if row['name'].find(r_input.value) >= 0]
#temp
@ref_computed
def cp_data():
  #r_input.value = r_input.value or ''
  return [row for row in rows.value if row['name'].find(r_input.value) >= 0]


#endregion

class Item(BaseModel):
  id: str
  name: str = None
  lasttime: Optional[int] = None
  lived: Optional[bool] = True


unrestricted_page_routes = {'/login','/pin','/auth/register'}
class AuthMiddleware(BaseHTTPMiddleware):
  async def dispatch(self, request, call_next):
    if not await user_check_token(app.storage.user.get('auth_token', None)):
        if request.url.path in Client.page_routes.values() and request.url.path not in unrestricted_page_routes:
            app.storage.user['referrer_path'] = request.url.path  # remember where the user wanted to go
            return RedirectResponse('/login')            
    
    # Remove original authorization header
    request.scope['headers'] = [e for e in request.scope['headers'] if not e[0] == b'authorization'] 
    # # add new authorization header
    request.scope['headers'].append((b'authorization', f"Bearer {app.storage.user.get('auth_token')}".encode()))
    
    return await call_next(request)

app.add_middleware(AuthMiddleware)


get_async_session_context = contextlib.asynccontextmanager(get_async_session)
get_user_db_context = contextlib.asynccontextmanager(get_user_db)
get_all_user_db_context = contextlib.asynccontextmanager(get_all_user_db)
get_user_manager_context = contextlib.asynccontextmanager(get_user_manager)
get_all_user_manager_context = contextlib.asynccontextmanager(get_all_user_manager)

def user_logout() -> None:
    app.storage.user.clear()
    ui.navigate.to('/login')


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


@ui.page('/login')
async def login_page() -> Optional[RedirectResponse]:
    async def try_login():
        user = await user_authenticate(email=email.value, password=password.value)
        token = await user_create_token(user)
        
        if token is not None:
            ui.notify('login!', color='negative')
            app.storage.user.update({'username': email.value, 'authenticated': True,'auth_token': token})
            ui.navigate.to(app.storage.user.get('referrer_path', '/'))  # go back to where the user wanted to go
        else:
            ui.notify('email or password wrong!', color='negative')

    #if await user_check_token(app.storage.user.get('auth_token', None)):
    #    return RedirectResponse('/')
          
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
  rows.value.append(item)
  return item


def DeleteRow(item):
  for row in rows.value:
    if row['key'] == item["id"]+item["name"]:
      rows.value.remove(row)
      return
  accountname = item["name"]
  SendMessage(f"Account:{accountname} is online")


#lock = threading.Lock()

def sendDiscord(message):

  # Your webhook URL
  #dsicord_webhook_url = 'YOUR_WEBHOOK_URL_HERE'

  # The message you want to send
  data = {
  "content": message
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
  for row in rows.value:
    if row['lasttime'] + checktime < datetime.now().timestamp():
      row['lived'] = False
      row['count'] = row['count'] + 1
      #sendDiscord(f"Account:{row['name']} is offline")
      if row['count'] > 3:
        rows.value.remove(row)
  #print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), len(rows.value))
  create_timer()


def create_timer():
    t = threading.Timer(1, checklived)  # 每60秒检查一次
    t.daemon = True  # 设置为守护线程
    t.start()

#,ssl_keyfile="./key.pem", ssl_certfile="./cert.pem"
ui.run(host="0.0.0.0",port=80,reload=True,storage_secret="none",title="mt5 heart beat")
threading.Thread(target=create_timer).start()

async def get_all_users():
    async with get_async_session_context() as session:
        async with get_all_user_db_context(session) as user_db:
            async with get_all_user_manager_context(user_db) as all_user_manager:
                users = await all_user_manager.getalluser()
                return users

@app.get("/api/all-users", response_model=List[UserRead])
async def read_all_users(user: User = Depends(current_active_user)):
    if not user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized")
    users=await get_all_users()
    return users
@app.post('/dark_mode')
async def _post_dark_mode(request: Request) -> None:
    print((await request.json()).get('value'))
@ui.page("/all-users")
async def allusers():  # Changed to async
    async def create() -> None:
        with ui.dialog() as dialog, ui.card():
            async def alert():
                time = await ui.run_javascript('Date()')
                ui.notify(f'Browser time: {time}')
            async def adduser():

                scripts=f'''
                           fetch('/auth/register', {{
                                method: 'POST',
                                headers: {{'Content-Type': 'application/json'}}, 
                                body: JSON.stringify({{"email": "{email.value}","password":"{password.value}"}})
                            }}).then(response => {{
                                if (!response.ok) {{  
                                    throw new Error(response.status+' '+response.text());
                                }}
                                return "User added successfully.";
                            }}).catch(error => {{
                                console.error('There was a problem with the fetch operation:', error); 
                                return "Failed add"
                            }})

                        '''
             
                result=await ui.run_javascript(scripts,timeout=10)
                ui.notify(result)
            email=ui.input("User Email"
              ).style("align-self:flex-start;font-size:1rem").props(
               'outlined clearable debounce="500"')
            password=ui.input("Password",password=True,password_toggle_button=True
              ).style("align-self:flex-start;font-size:1rem").props(
               'outlined debounce="500" type="password"')
            with ui.row():
                ui.button('Create', on_click=adduser)
            
        dialog.open()

        
    ui.button(on_click=create, icon='add').props('flat').classes('ml-auto')
    columns = [
        {
            'name': 'id',
            'label': 'ID',
            'field': 'id',
            'required': True,
            'align': 'left'
        },
        {
            'name': 'email',
            'label': 'Email',
            'field': 'email',
            'sortable': True,
            'align': 'left'
        },
        {
            'name': 'is_superuser',
            'label': 'Is Superuser',
            'field': 'is_superuser',
            'sortable': False,
            'align': 'left'
        }
    ]
    users = await get_all_users()  # This can now use await
    allusers= [{"id": user.id, "email": user.email, "is_superuser": user.is_superuser} for user in users]
    async def delete(e: events.GenericEventArguments) -> None:
        result=await delete_user(e.args['id'])
        if result:
           allusers[:] = [row for row in allusers if row['id'] != UUID(e.args['id'])]
           ui.notify(f'Deleted user: {e.args["email"]}')
           table.update()
        else:
           ui.notify(f'Failed to delete user: {e.args["email"]}')
           
    async def reset(e: events.GenericEventArguments) -> None:
        #rows[:] = [row for row in rows if row['id'] != e.args['id']]
        await resetpassword(e.args['email'])
    async def resetpassword(email):
        scripts=f'''
                fetch('auth/forgot-password', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}}, 
                    body: JSON.stringify({{"email": "{email}"}})
                }}).then(response => {{
                    if (!response.ok) {{  
                        throw new Error(response.status);
                    }}
                    return "Reset user password to '123456'.";
                }}).catch(error => {{
                    console.error('There was a problem with the fetch operation:', error); 
                    return "Reset failed"
                }})

            '''
        #print("scripts:"+scripts) 
        result=await ui.run_javascript(scripts,timeout=10)
        #print(result)
        ui.notify(f'result is {result}')


    table = rxui.table(columns=columns, rows=allusers, row_key='id',
                    pagination=15).style("height:auto;width:100%")
    table.add_slot('header', r'''
        <q-tr :props="props">
           
            <q-th v-for="col in props.cols" :key="col.name" :props="props">
                {{ col.label }}
            </q-th>
            <q-th auto-width key="reset" />
            <q-th auto-width key="delete"/>
        </q-tr>
    ''')
    table.add_slot('body', r'''
    <q-tr :props="props">
        <q-td key="id" :props="props">
            {{ props.row.id }}    
        </q-td>
        <q-td key="email" :props="props">
            {{ props.row.email }}    
        </q-td> 
        <q-td key="is_superuser" :props="props">
            {{ props.row.is_superuser }}    
        </q-td>    
        <q-td auto-width >
            <q-btn size="sm" color="warning" round dense icon="delete"
                @click="() => $parent.$emit('delete', props.row)"
            />
        </q-td>
        <q-td auto-width >
            <q-btn size="sm" color="warning" round dense icon="refresh"
                @click="() => $parent.$emit('reset', props.row)"
            />
        </q-td>
    </q-tr>
    ''')
    table.on('reset', reset)
    table.on('delete', delete)
async def delete_user(id: UUID) -> bool:
    try:
        async with get_async_session_context() as session:
            async with get_user_db_context(session) as user_db:
                async with get_user_manager_context(user_db) as user_manager:
                    user=await user_manager.get(id)
                    if user is None:
                        return False
                    await user_manager.delete(user)
                    return True
    except:
        return False
