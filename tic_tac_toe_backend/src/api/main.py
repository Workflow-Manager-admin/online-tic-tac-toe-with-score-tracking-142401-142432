from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
import sqlite3
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

# --- Constants/config ---
DATABASE_PATH = "tic_tac_toe.db"  # assumes db placed in working directory
SECRET_KEY = "CHANGE_THIS_SECRET"  # Should be overwritten via env in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 12 * 60   # 12 hours

# --- App init & CORS ---
app = FastAPI(
    title="Tic Tac Toe FastAPI Backend",
    description="REST backend for online tic tac toe with score tracking",
    version="1.0.0",
    openapi_tags=[
        {"name": "Auth", "description": "User registration and login"},
        {"name": "Game", "description": "Game lifecycle and board management"},
        {"name": "Score", "description": "Score and leaderboard APIs"}
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Password hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Database helpers ---
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    # Users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        score INTEGER NOT NULL DEFAULT 0
    )
    """)
    # Games
    cur.execute("""
    CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_x INTEGER NOT NULL,
        player_o INTEGER NOT NULL,
        board TEXT NOT NULL, -- stores a 9-char string (row-major)
        current_turn TEXT NOT NULL, -- 'X' or 'O'
        status TEXT NOT NULL, -- 'ongoing', 'finished'
        winner TEXT, -- 'X', 'O', 'draw', or NULL if ongoing
        created_at TEXT,
        updated_at TEXT,
        FOREIGN KEY(player_x) REFERENCES users(id),
        FOREIGN KEY(player_o) REFERENCES users(id)
    )
    """)
    # Moves
    cur.execute("""
    CREATE TABLE IF NOT EXISTS moves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game_id INTEGER NOT NULL,
        player INTEGER NOT NULL,
        position INTEGER NOT NULL, -- 0-8
        symbol TEXT NOT NULL, -- 'X' or 'O'
        moved_at TEXT,
        FOREIGN KEY(game_id) REFERENCES games(id),
        FOREIGN KEY(player) REFERENCES users(id)
    )
    """)
    conn.commit()
    conn.close()

# --- Utility Classes ---
class Token(BaseModel):
    access_token: str
    token_type: str

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, description="Username")

    password: str = Field(..., min_length=5, max_length=64, description="Password")

class UserPublic(BaseModel):
    id: int
    username: str
    score: int

class MoveRequest(BaseModel):
    position: int = Field(..., description="The board position (0-8) to make a move.")

class GameCreateRequest(BaseModel):
    opponent_username: str = Field(..., description="Username of the opponent to play against.")

class GamePublic(BaseModel):
    id: int
    player_x: str
    player_o: str
    board: str
    current_turn: str
    status: str
    winner: Optional[str]
    created_at: str
    updated_at: str

class MovePublic(BaseModel):
    id: int
    player: str
    position: int
    symbol: str
    moved_at: str

class LeaderboardEntry(BaseModel):
    username: str
    score: int

# --- Security helpers ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_username(db_conn, username: str):
    res = db_conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return res

def get_user_by_id(db_conn, user_id: int):
    return db_conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()

# --- Auth dependencies ---
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    conn = get_db()
    user = get_user_by_username(conn, username)
    conn.close()
    if user is None:
        raise credentials_exception
    return user

# --- Game logic helpers ---
def parse_board(board: str):
    # Returns a 3x3 matrix from a 9-char string
    return [list(board[i*3:(i+1)*3]) for i in range(3)]

def stringify_board(matrix):
    return "".join(cell for row in matrix for cell in row)

def get_game_status(board: str):
    mat = parse_board(board)
    # Rows, columns and diagonals win check
    lines = mat + [list(col) for col in zip(*mat)] + [
        [mat[i][i] for i in range(3)], [mat[i][2-i] for i in range(3)]]
    for line in lines:
        if line == ['X', 'X', 'X']:
            return "X"
        if line == ['O', 'O', 'O']:
            return "O"
    if " " not in board:
        return "draw"
    return "ongoing"

# --- API Routes ---

# Health check
@app.get("/", tags=["Health"])
def health_check():
    """PUBLIC_INTERFACE
    Returns simple health message for deployment checks.
    """
    return {"message": "Healthy"}

# --- AUTH APIs ---
# PUBLIC_INTERFACE
@app.post("/register", response_model=UserPublic, tags=["Auth"], summary="Register a new user")
def register(user: UserRegister):
    """
    Register a new user with username and password.
    """
    conn = get_db()
    hashed_password = get_password_hash(user.password)
    try:
        conn.execute(
            "INSERT INTO users (username, password, score) VALUES (?, ?, ?)",
            (user.username, hashed_password, 0)
        )
        conn.commit()
        user_row = get_user_by_username(conn, user.username)
        return UserPublic(id=user_row["id"], username=user_row["username"], score=user_row["score"])
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already registered.")
    finally:
        conn.close()

# PUBLIC_INTERFACE
@app.post("/token", response_model=Token, tags=["Auth"], summary="Get JWT token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login via username and password, returns JWT access token.
    """
    conn = get_db()
    user = get_user_by_username(conn, form_data.username)
    conn.close()
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return Token(access_token=access_token, token_type="bearer")

# --- GAME APIs ---
# PUBLIC_INTERFACE
@app.post("/game", response_model=GamePublic, tags=["Game"], summary="Start a new game")
def start_game(req: GameCreateRequest, current_user=Depends(get_current_user)):
    """
    Start a new tic tac toe game vs another user. You will be X, opponent is O.
    """
    conn = get_db()
    op = get_user_by_username(conn, req.opponent_username)
    if not op:
        conn.close()
        raise HTTPException(status_code=404, detail="Opponent does not exist")
    cur = conn.execute(
        "INSERT INTO games (player_x, player_o, board, current_turn, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (current_user["id"], op["id"], " " * 9, "X", "ongoing", datetime.utcnow().isoformat(), datetime.utcnow().isoformat())
    )
    conn.commit()
    gid = cur.lastrowid
    game = conn.execute("SELECT * FROM games WHERE id=?", (gid,)).fetchone()
    p_x = get_user_by_id(conn, game["player_x"])
    p_o = get_user_by_id(conn, game["player_o"])
    conn.close()
    return GamePublic(
        id=game["id"], player_x=p_x["username"], player_o=p_o["username"], board=game["board"],
        current_turn=game["current_turn"], status=game["status"], winner=game["winner"],
        created_at=game["created_at"], updated_at=game["updated_at"]
    )

# PUBLIC_INTERFACE
@app.post("/game/{game_id}/move", response_model=GamePublic, tags=["Game"], summary="Submit a move")
def submit_move(game_id: int, move: MoveRequest, current_user=Depends(get_current_user)):
    """
    Submit a move (board position) for current user in a specific game.
    Returns updated game info.
    """
    conn = get_db()
    game = conn.execute("SELECT * FROM games WHERE id=?", (game_id,)).fetchone()
    if not game:
        conn.close()
        raise HTTPException(status_code=404, detail="Game not found.")
    if game["status"] != "ongoing":
        conn.close()
        raise HTTPException(status_code=400, detail="Game is already finished.")
    # Check turn
    player_role = None
    if game["player_x"] == current_user["id"]:
        player_role = "X"
    elif game["player_o"] == current_user["id"]:
        player_role = "O"
    if not player_role:
        conn.close()
        raise HTTPException(status_code=403, detail="You are not a player in this game.")
    if player_role != game["current_turn"]:
        conn.close()
        raise HTTPException(status_code=409, detail="It's not your turn!")
    # Make move
    board = list(game["board"])
    pos = move.position
    if not 0 <= pos < 9 or board[pos] != " ":
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid move: position taken or out of bounds.")
    board[pos] = player_role
    new_board_str = "".join(board)
    result = get_game_status(new_board_str)
    # Move: add row to moves
    conn.execute(
        "INSERT INTO moves (game_id, player, position, symbol, moved_at) VALUES (?, ?, ?, ?, ?)",
        (game_id, current_user["id"], pos, player_role, datetime.utcnow().isoformat())
    )
    update_status = (
        "finished" if result in ["X", "O", "draw"] else "ongoing"
    )
    conn.execute(
        "UPDATE games SET board=?, current_turn=?, status=?, winner=?, updated_at=? WHERE id=?",
        (
            new_board_str,
            "O" if player_role == "X" else "X",
            update_status,
            result if result in ["X", "O", "draw"] else None,
            datetime.utcnow().isoformat(),
            game_id,
        )
    )
    # Update scores if finished
    if update_status == "finished":
        if result == "X":
            conn.execute("UPDATE users SET score=score+1 WHERE id=?", (game["player_x"],))
        elif result == "O":
            conn.execute("UPDATE users SET score=score+1 WHERE id=?", (game["player_o"],))
        # No points for draw
    conn.commit()
    updated_game = conn.execute("SELECT * FROM games WHERE id=?", (game_id,)).fetchone()
    p_x = get_user_by_id(conn, updated_game["player_x"])
    p_o = get_user_by_id(conn, updated_game["player_o"])
    conn.close()
    return GamePublic(
        id=updated_game["id"], player_x=p_x["username"], player_o=p_o["username"], board=updated_game["board"],
        current_turn=updated_game["current_turn"], status=updated_game["status"], winner=updated_game["winner"],
        created_at=updated_game["created_at"], updated_at=updated_game["updated_at"]
    )

# PUBLIC_INTERFACE
@app.get("/game/{game_id}", response_model=GamePublic, tags=["Game"], summary="Get board state")
def get_board_state(game_id: int, current_user=Depends(get_current_user)):
    """
    Get the full state of a particular game (board, turns, etc).
    """
    conn = get_db()
    game = conn.execute("SELECT * FROM games WHERE id=?", (game_id,)).fetchone()
    if not game:
        conn.close()
        raise HTTPException(status_code=404, detail="Game not found.")
    if current_user["id"] not in [game["player_x"], game["player_o"]]:
        conn.close()
        raise HTTPException(status_code=403, detail="Not authorized to view this game.")
    p_x = get_user_by_id(conn, game["player_x"])
    p_o = get_user_by_id(conn, game["player_o"])
    conn.close()
    return GamePublic(
        id=game["id"], player_x=p_x["username"], player_o=p_o["username"], board=game["board"],
        current_turn=game["current_turn"], status=game["status"], winner=game["winner"],
        created_at=game["created_at"], updated_at=game["updated_at"]
    )

# PUBLIC_INTERFACE
@app.get("/game/{game_id}/moves", response_model=List[MovePublic], tags=["Game"], summary="Get all moves in a game")
def get_moves(game_id: int, current_user=Depends(get_current_user)):
    """
    Returns chronological list of moves played in a game.
    """
    conn = get_db()
    game = conn.execute("SELECT * FROM games WHERE id=?", (game_id,)).fetchone()
    if not game:
        conn.close()
        raise HTTPException(status_code=404, detail="Game not found.")
    if current_user["id"] not in [game["player_x"], game["player_o"]]:
        conn.close()
        raise HTTPException(status_code=403, detail="Not authorized to view the moves.")
    moves = conn.execute(
        "SELECT moves.*, users.username as username FROM moves JOIN users ON moves.player = users.id WHERE game_id=? ORDER BY id ASC",
        (game_id,)
    ).fetchall()
    conn.close()
    return [
        MovePublic(
            id=row["id"], player=row["username"], position=row["position"], symbol=row["symbol"], moved_at=row["moved_at"]
        ) for row in moves
    ]

# PUBLIC_INTERFACE
@app.get("/me/games", response_model=List[GamePublic], tags=["Game"], summary="Get user's games")
def get_my_games(current_user=Depends(get_current_user)):
    """
    Retrieve all games involving the current user.
    """
    conn = get_db()
    games = conn.execute(
        "SELECT * FROM games WHERE player_x=? OR player_o=? ORDER BY updated_at DESC", (current_user["id"], current_user["id"])
    ).fetchall()
    res = []
    for g in games:
        p_x = get_user_by_id(conn, g["player_x"])
        p_o = get_user_by_id(conn, g["player_o"])
        res.append(GamePublic(
            id=g["id"], player_x=p_x["username"], player_o=p_o["username"], board=g["board"],
            current_turn=g["current_turn"], status=g["status"], winner=g["winner"],
            created_at=g["created_at"], updated_at=g["updated_at"]
        ))
    conn.close()
    return res

# PUBLIC_INTERFACE
@app.get("/leaderboard", response_model=List[LeaderboardEntry], tags=["Score"], summary="Leaderboard")
def get_leaderboard():
    """
    Returns the top 10 users by score.
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT username, score FROM users ORDER BY score DESC, username ASC LIMIT 10"
    ).fetchall()
    conn.close()
    return [LeaderboardEntry(username=row["username"], score=row["score"]) for row in rows]

# PUBLIC_INTERFACE
@app.get("/me", response_model=UserPublic, tags=["Score"], summary="Current user's public info")
def me(current_user=Depends(get_current_user)):
    """
    Returns public info (id, username, score) of the current user.
    """
    return UserPublic(
        id=current_user["id"], username=current_user["username"], score=current_user["score"]
    )

# Run DB init if needed
init_db()
