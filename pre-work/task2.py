import os
return jwt.decode(token, PUBLIC_KEY_PEM, algorithms=["RS256"], audience="secure-api-clients", options=options)




async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
# Extract and verify JWT
try:
payload = decode_token(token)
username = payload.get("sub")
if not username:
raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token: missing subject")
except jwt.ExpiredSignatureError:
raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
except jwt.InvalidTokenError as e:
raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {str(e)}")


# Load user
user = db.query(User).filter(User.username == username).first()
if not user:
raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
return user


# =========================
# Routes
# =========================


@app.get("/health")
async def health():
return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}




@app.post("/register", response_model=ProfileResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: Session = Depends(get_db)):
# Basic password policy demonstration: length checked by Pydantic; add more if needed
password_hash = hash_password(payload.password)
user = User(username=payload.username, password_hash=password_hash)
db.add(user)
try:
db.commit()
db.refresh(user)
except IntegrityError:
db.rollback()
raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")


return ProfileResponse(id=user.id, username=user.username)




@app.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: Session = Depends(get_db)):
user = db.query(User).filter(User.username == payload.username).first()
if not user or not verify_password(payload.password, user.password_hash):
# Do not reveal which part failed
raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
token = create_access_token(subject=user.username, expires_delta=expires_delta)
return TokenResponse(access_token=token, expires_in=int(expires_delta.total_seconds()))




@app.get("/profile", response_model=ProfileResponse)
async def profile(current_user: User = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
# Optionally show token issuance time from JWT
try:
payload = decode_token(token)
iat = payload.get("iat")
issued_at = datetime.fromtimestamp(iat, tz=timezone.utc) if isinstance(iat, int) else None
except Exception:
issued_at = None


return ProfileResponse(id=current_user.id, username=current_user.username, token_issued_at=issued_at)




# Entry point for `python secure_api.py`
if __name__ == "__main__":
import uvicorn


port = int(os.getenv("PORT", "8000"))
uvicorn.run("secure_api:app", host="0.0.0.0", port=port, reload=False)
