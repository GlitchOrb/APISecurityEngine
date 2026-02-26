# Object-Level Authorization Guards (BOLA/IDOR Defenses)

Broken Object Level Authorization (BOLA), historically known as IDOR, occurs when an application fails to properly validate that the currently authenticated user is authorized to perform the requested action on the explicitly requested object ID (e.g., `userId`, `documentId`).

## Defensive Strategy
Always query elements from the database bound explicitly to the authenticated user's ownership context, rather than retrieving the item by parameters alone and validating later.

---

### Python (FastAPI + SQLAlchemy)

```python
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .database import get_db
from .models import Document, User
from .auth import get_current_user

router = APIRouter()

@router.get("/documents/{document_id}")
def get_document(
    document_id: int, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    # We bind the query natively to the owner_id using the authenticated user.
    # If Document 5 exists but belongs to someone else, this returns None.
    document = db.query(Document).filter(
        Document.id == document_id, 
        Document.owner_id == current_user.id
    ).first()
    
    if not document:
        # Note: Do not reveal if the document exists under another owner.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Document not found"
        )
        
    return document
```

---

### Node.js (Express + Prisma)

```javascript
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const authenticateToken = require('./middleware/auth');

const router = express.Router();
const prisma = new PrismaClient();

router.get('/documents/:documentId', authenticateToken, async (req, res) => {
    const documentId = parseInt(req.params.documentId);
    if (isNaN(documentId)) {
        return res.status(400).send("Invalid document ID");
    }

    // Combining the where clause limits the lookup domain strictly to the
    // currently authenticated user's ID derived from their JWT token.
    const document = await prisma.document.findFirst({
        where: {
            id: documentId,
            ownerId: req.user.id // Bound from token payload in middleware
        }
    });

    if (!document) {
        return res.status(404).send("Document not found");
    }

    res.json(document);
});

module.exports = router;
```
