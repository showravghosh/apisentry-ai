from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session

import models
import schemas
import auth
from database import engine, get_db, Base
from logger import LoggingMiddleware

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="APISentry Test API",
    description="AI security gateway test target REST API",
    version="1.0.0",
)

app.add_middleware(LoggingMiddleware)


@app.get("/")
def root():
    return {"message": "APISentry Test API is running", "docs": "/docs"}


@app.post("/register", tags=["auth"])
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")

    new_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=auth.hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered", "user_id": new_user.id}


@app.post("/login", tags=["auth"])
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if not db_user or not auth.verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth.create_access_token({"sub": db_user.username})
    return {"access_token": token, "token_type": "bearer", "user_id": db_user.id}


@app.get("/search", tags=["products"])
def search_products(q: str = "", db: Session = Depends(get_db)):
    results = db.query(models.Product).filter(models.Product.name.ilike(f"%{q}%")).all()
    return {"query": q, "count": len(results), "results": [r.name for r in results]}


@app.get("/products", response_model=list[schemas.ProductOut], tags=["products"])
def list_products(db: Session = Depends(get_db)):
    return db.query(models.Product).all()


@app.get("/products/{product_id}", response_model=schemas.ProductOut, tags=["products"])
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.query(models.Product).filter(models.Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


@app.post("/products", response_model=schemas.ProductOut, tags=["products"])
def add_product(
    product: schemas.ProductCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    new_product = models.Product(**product.model_dump())
    db.add(new_product)
    db.commit()
    db.refresh(new_product)
    return new_product


@app.post("/cart/add", tags=["cart"])
def add_to_cart(
    item: schemas.CartAdd,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    product = db.query(models.Product).filter(models.Product.id == item.product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    cart_item = models.CartItem(
        user_id=current_user.id,
        product_id=item.product_id,
        quantity=item.quantity,
    )
    db.add(cart_item)
    db.commit()
    db.refresh(cart_item)
    return {"message": "Item added to cart", "cart_item_id": cart_item.id}


@app.get("/cart", response_model=list[schemas.CartItemOut], tags=["cart"])
def view_cart(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    return db.query(models.CartItem).filter(models.CartItem.user_id == current_user.id).all()


@app.post("/order", tags=["order"])
def place_order(order: dict, db: Session = Depends(get_db),
                current_user: models.User = Depends(auth.get_current_user)):
    product = db.query(models.Product).filter(models.Product.id == order.get("product_id")).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    quantity = order.get("quantity", 1)
    total = product.price * quantity
    return {"message": "Order placed", "total": total}


@app.get("/users/{user_id}", response_model=schemas.UserOut, tags=["users"])
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(auth.get_current_user),
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
