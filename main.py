import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from datetime import timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.models import Model
from tortoise.contrib.pydantic import pydantic_model_creator
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


JWT_SECRET = '1f5990328a44a2f7ccc726a06a7f044eca2a809808b108bae233430cf4e7fec1c3f007abfb8d1ef4cdab5bf3a46b01f68099f9b8cee32288e03420a330965875'


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)

    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


User_Pydantic = pydantic_model_creator(User, name="User")
UserIn_Pydantic = pydantic_model_creator(
    User, name='UserIn', exclude_readonly=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user or not user.verify_password(password):
        return False
    return user


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = await User.get(id=payload["id"])
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await User_Pydantic.from_tortoise_orm(user)


@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        return {'message': 'Invalid username or password'}
    user_obj = await User_Pydantic.from_tortoise_orm(user)
    token = jwt.encode(
        {"id": user_obj.id, "username": user_obj.username}, JWT_SECRET, algorithm='HS256')
    return {'access_token': token, 'token_type': 'bearer'}


@app.get('/users/me')
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user


@app.post('/users', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(username=user.username,
                    password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    user = await User_Pydantic.from_tortoise_orm(user_obj)


register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["main"]},
    generate_schemas=True,
    add_exception_handlers=True,
)
