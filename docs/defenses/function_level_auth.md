# Function-Level Authorization Guards (BFLA Defenses)

Broken Function Level Authorization occurs when endpoints responsible for privileged operations (e.g., admin tasks, billing overrides, account suspensions) are not properly protected by role-based or attribute-based access controls (RBAC/ABAC), relying merely on the fact that standard users cannot see the URL in their UI.

## Defensive Strategy
Explicitly require roles assigned to tokens or sessions immediately upon route invocation before any business logic occurs.

---

### Python (FastAPI + JWT Roles)

```python
from fastapi import APIRouter, Depends, HTTPException, status
from typing import Annotated

router = APIRouter()

# Assuming a dependency `get_current_user` extracts JWT claims
class RequiresRole:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: Annotated[User, Depends(get_current_user)]):
        if user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return user

# Endpoint explicitly wraps the dependency forcing the checking of 'admin' role.
@router.post("/admin/suspend/{user_id}", dependencies=[Depends(RequiresRole(["admin"]))])
def suspend_user(user_id: int):
    # Perform suspension logic securely here
    return {"message": f"User {user_id} suspended"}
```

---

### Node.js (Express Middleware)

```javascript
// middleware/requireRole.js
function requireRole(allowedRoles) {
    return (req, res, next) => {
        // Assert token was parsed
        if (!req.user || !req.user.role) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        // Check if user holds any of the permitted roles
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: "Forbidden: Insufficient privileges" });
        }

        next();
    };
}

module.exports = requireRole;

// routes/admin.js
const express = require('express');
const requireRole = require('../middleware/requireRole');
const router = express.Router();

// Enforces that only users with 'ADMIN' array claims can proceed.
router.post('/suspend/:userId', requireRole(['ADMIN', 'SUPERADMIN']), (req, res) => {
    // Perform suspension logic here
    res.json({ message: `User ${req.params.userId} suspended` });
});
```
