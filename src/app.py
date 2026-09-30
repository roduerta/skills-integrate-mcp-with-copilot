"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import hashlib
import hmac
import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

SESSION_COOKIE_NAME = "teacher_session"
SESSION_DURATION_SECONDS = 8 * 60 * 60


class LoginRequest(BaseModel):
    username: str
    password: str


def get_teacher_config():
    username = os.getenv("TEACHER_USERNAME")
    password = os.getenv("TEACHER_PASSWORD")
    secret = os.getenv("SESSION_SECRET")
    if not username or not password or not secret or len(secret) < 32:
        raise HTTPException(
            status_code=503,
            detail="Teacher sign-in is not configured",
        )
    return username, password, secret


def encode_token_part(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def create_session_token(username: str, secret: str) -> str:
    expires_at = int(time.time()) + SESSION_DURATION_SECONDS
    payload = encode_token_part(f"{username}:{expires_at}".encode("utf-8"))
    signature = hmac.new(
        secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256
    ).digest()
    return f"{payload}.{encode_token_part(signature)}"


def is_teacher_authenticated(request: Request) -> bool:
    try:
        configured_username, _, secret = get_teacher_config()
    except HTTPException:
        return False

    token = request.cookies.get(SESSION_COOKIE_NAME, "")
    try:
        payload, supplied_signature = token.split(".", 1)
        expected_signature = encode_token_part(
            hmac.new(
                secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256
            ).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return False

        decoded_payload = base64.urlsafe_b64decode(
            payload + "=" * (-len(payload) % 4)
        ).decode("utf-8")
        username, expires_at = decoded_payload.rsplit(":", 1)
        return username == configured_username and int(expires_at) > int(time.time())
    except (ValueError, UnicodeError, TypeError):
        return False


def require_teacher(request: Request) -> None:
    if not is_teacher_authenticated(request):
        raise HTTPException(status_code=401, detail="Teacher login required")


@app.post("/auth/login")
def teacher_login(credentials: LoginRequest, response: Response):
    username, password, secret = get_teacher_config()
    if not (
        hmac.compare_digest(credentials.username, username)
        and hmac.compare_digest(credentials.password, password)
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=create_session_token(username, secret),
        max_age=SESSION_DURATION_SECONDS,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
        samesite="strict",
        path="/",
    )
    return {"message": "Teacher login successful"}


@app.get("/auth/session")
def teacher_session(request: Request):
    return {"authenticated": is_teacher_authenticated(request)}


@app.post("/auth/logout")
def teacher_logout(response: Response):
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
        samesite="strict",
        path="/",
    )
    return {"message": "Teacher logged out"}

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str, request: Request):
    """Sign up a student for an activity"""
    require_teacher(request)

    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str, request: Request):
    """Unregister a student from an activity"""
    require_teacher(request)

    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
