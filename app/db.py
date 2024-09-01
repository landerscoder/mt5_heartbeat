from typing import AsyncGenerator, Generic, Optional, Type, TypeVar
from sqlalchemy import select  # Add select import

from fastapi import Depends
from fastapi_users.db import SQLAlchemyBaseUserTableUUID, SQLAlchemyUserDatabase, BaseUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite+aiosqlite:///./test.db"
Base: DeclarativeMeta = declarative_base()

UP = TypeVar("UP", bound=SQLAlchemyBaseUserTableUUID)
ID = TypeVar("ID")

class UserDatabase(BaseUserDatabase[UP, ID]):
    """
    Database adapter for SQLAlchemy.

    :param session: SQLAlchemy session instance.
    :param user_table: SQLAlchemy user model.
    """

    session: AsyncSession
    user_table: Type[UP]

    def __init__(
        self,
        session: AsyncSession,
        user_table: Type[UP],
    ):
        self.session = session
        self.user_table = user_table
    async def get_all_user(self):
        statement = select(self.user_table)
        results = await self.session.execute(statement)
        return results.scalars().all()
    
class User(SQLAlchemyBaseUserTableUUID, Base):
    pass


engine = create_async_engine(DATABASE_URL)
async_session_maker = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def create_db_and_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session


async def get_user_db(session: AsyncSession = Depends(get_async_session)):
    yield SQLAlchemyUserDatabase(session, User)

async def get_all_user_db(session: AsyncSession = Depends(get_async_session)):
    yield UserDatabase(session, User)