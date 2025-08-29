from fastapi import FastAPI,status,HTTPException, Request
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr
from datetime import date, datetime
from enum import Enum
from bcrypt import checkpw, hashpw, gensalt
from functools import wraps
import jwt
from bson import ObjectId



app = FastAPI()

client = AsyncIOMotorClient("mongodb+srv://sdreddy06:sdreddy06@cluster0.kwdkleh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client["Data"]
user_collection = db["users"]
book_collection = db["books"]

class UserRole(str,Enum):
    admin = "admin"
    author = "author"
    viewer = "viewer"

class User(BaseModel):
    name:str = Field(...,min_length=1)
    email:EmailStr
    password:str = Field(...,min_length=5)
    role:UserRole = Field(...,min_length=1)

class Book(BaseModel):
    created_by:str = Field(...,min_length=1)
    name:str = Field(...,min_length=1)
    publish_date:str  = Field(...)
    author:str = Field(...,min_length=1)
    price:int = Field(...)
    category:str = Field(...,min_length=1)

@app.post("/register")
async def register_user(user:User):

    try:
        userObject = User.model_dump(user)

        existUser = await user_collection.find_one({"email":userObject["email"]})

        if(existUser):
             return "Email already in use"

        userObject["password"] =  hashpw(user.password.encode("utf-8"),gensalt()).decode("utf-8")

        userFetch = await user_collection.insert_one(userObject)
        return "User Registered"
    except:
        return "All feilds are required"
    
class LoginUser(BaseModel):
    email:str
    password:str

@app.post("/login")
async def login_user(user:LoginUser):

    # try:

        userDetails = LoginUser.model_dump(user)
        
        email = userDetails["email"]
        password = userDetails["password"]
    
        existUser = await user_collection.find_one({"email":email})

        print(existUser)

        if(not existUser):
            return "Email not registered"

        isMatch = checkpw(password.encode("utf-8"),existUser["password"].encode("utf-8"))

        if(isMatch):
            
            payload = {
                "id": str(existUser["_id"]),  
                "email": existUser["email"],
                "role": existUser["role"]
            }

            token = jwt.encode(payload,"secretkey","HS256")

            return {"message":"Logged in","token":token}
        
    # except:
    #     return "Error in Login Api"

def auth_required(role = None):
    def dec_1(fn):
        @wraps(fn)
        async def decorated(req:Request,*args,**kwargs):

            try:
                token = req.headers["authorization"].split(" ")[1]

            except(IndexError):
                raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail = "Token not provided , not authorized")

            try:
                data = jwt.decode(token,"secretkey","HS256")

                if(role == None):
                    print("No Role required")
                elif( not (data["role"] in role)):
                    return "Not Auhtorized"
                req.state.user = data

            except jwt.InvalidSignatureError:
                raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail = "not authorized")
            
            return await fn(req,*args,**kwargs)
        return decorated
    return dec_1

@app.post("/createBook")
@auth_required(["admin","author"])
async def add_book(req:Request,book:Book):
    try:
        book_object = book.model_dump()

        exist_book = await book_collection.find_one({"name":book_object["name"]})

        if(exist_book):
            return "Book already added"
        
        add_book = await book_collection.insert_one(book_object)

        return "Book added"
    except:
        return "Error in create Book api"

@app.put("/editBook/{bookId}")
@auth_required(["admin","author"])
async def edit_book(req:Request,bookId:str,updated_book:Book):

    try:

        user = req.state.user

        print(bookId)

        exist_book = await book_collection.find_one({"_id":ObjectId(bookId)})

        print(exist_book)

        if(not exist_book):
            return "Book doesnt exist"
        
        if (exist_book["created_by"] == user["email"] or user["role"] == "admin" or exist_book["author"] == user["name"]):

            updated_data = updated_book.model_dump()

            await book_collection.update_one({"_id":ObjectId(bookId)},{"$set":updated_data})

            return "Book Edited"
        
        return "Not authorized"
    except:
        return "Error in edit Book"

def book_format(book):
    return {
        "id":str(book.get("_id")),
        "name":book.get("name"),
        "author":book.get("author"),
        "category":book.get("category"),
        "price":book.get("price")
    }

@app.get("/getBooks")
@auth_required(["admin","author","viewer"])
async def get_books(req:Request,category:str=None,author:str = None):
    try:

        query = {}

        if category:
            query["category"] = category
        
        if author:
            query["author"] = author

        cursor = await book_collection.find(query).to_list()
        books = []
        
        for book in cursor:
            books.append(book_format(book))
            
        if(books):
            return {"books":books}
        return "No Books found"
    
    except:
        return "error in get books"

@app.delete("/deleteBook/{bookId}")
@auth_required(["admin","author"])
async def delete_book(req:Request,bookId:str):

    delete = await book_collection.delete_one({"_id":ObjectId(bookId)})

    if(delete.deleted_count == 1):
        return "Book Deleted"
    return "Book Not Found"
