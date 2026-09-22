"""Shared FastAPI dependencies: DB session, current user/session, authorization.

Not a service module — no business logic lives here, only request-level
dependency resolution used by every route handler.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.constants import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.database import get_db
from app.models import User
from app.security import authorization as rbac
from app.security.authentication import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/token", auto_error=False
)

DbSession = Annotated[Session, Depends(get_db)]


def get_optional_token(request: Request) -> str | None:
    """Resolve an access token from Authorization header or secure-ish cookie."""
    auth = request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.cookies.get("mlinziops_token")


TokenDep = Annotated[str | None, Depends(get_optional_token)]


def get_current_user(
    db: DbSession,
    token: TokenDep,
    request: Request,
) -> User:
    """Resolve the authenticated user, raising 401 when missing/invalid."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    user_id = payload.get("sub")
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token subject")
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive or not found")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def current_session(request: Request, user: CurrentUser) -> dict:
    """Bundle the user + client IP for handlers that need both."""
    return {"user": user, "ip": request.client.host if request.client else None}


SessionDep = Annotated[dict, Depends(current_session)]


# --- Role-based dependency factories -------------------------------------
def require_role(*roles: str):
    def _dep(user: CurrentUser):
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return Depends(_dep)


def require_capability(capability: str):
    def _dep(user: CurrentUser):
        if not rbac.role_allows(user.role, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return Depends(_dep)


AdminOnly = require_role(ROLE_ADMIN)
StaffOnly = require_role(ROLE_ADMIN, ROLE_ANALYST)
