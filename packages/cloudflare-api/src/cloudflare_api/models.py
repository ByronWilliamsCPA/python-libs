"""Pydantic models for Cloudflare API responses.

Type-safe models for IP lists, items, and bulk operations.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ListKind(str, Enum):
    """Types of Cloudflare lists."""

    IP = "ip"
    REDIRECT = "redirect"
    HOSTNAME = "hostname"
    ASN = "asn"


class BulkOperationStatus(str, Enum):
    """Status of a bulk operation."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class IPListItem(BaseModel):
    """An item in an IP list.

    Attributes:
        id: Unique identifier for the item
        ip: IP address or CIDR range
        comment: Optional description
        created_on: When the item was created
        modified_on: When the item was last modified
    """

    id: str | None = None
    ip: str = Field(description="IP address or CIDR range")
    comment: str | None = Field(default=None, description="Optional description")
    created_on: datetime | None = None
    modified_on: datetime | None = None


class IPList(BaseModel):
    """A Cloudflare IP list.

    Attributes:
        id: Unique identifier for the list
        name: List name (must be unique per account)
        description: Optional description
        kind: Type of list (ip, redirect, hostname, asn)
        num_items: Number of items in the list
        num_referencing_filters: Number of firewall filters using this list
        created_on: When the list was created
        modified_on: When the list was last modified
    """

    id: str
    name: str
    description: str | None = None
    kind: ListKind = ListKind.IP
    num_items: int = 0
    num_referencing_filters: int = 0
    created_on: datetime | None = None
    modified_on: datetime | None = None


class BulkOperation(BaseModel):
    """Status of a bulk operation.

    Attributes:
        id: Operation identifier
        status: Current status
        error: Error message if failed
        completed: When the operation completed
    """

    id: str
    status: BulkOperationStatus
    error: str | None = None
    completed: datetime | None = None


class IPListItemInput(BaseModel):
    """Input model for creating/updating IP list items.

    Attributes:
        ip: IP address or CIDR range
        comment: Optional description
    """

    ip: str = Field(description="IP address or CIDR range")
    comment: str | None = Field(default=None, description="Optional description")

    def to_api_dict(self) -> dict[str, Any]:
        """Convert to API request format.

        Returns:
            Dictionary for API request.
        """
        result: dict[str, Any] = {"ip": self.ip}
        if self.comment:
            result["comment"] = self.comment
        return result


class CreateIPListRequest(BaseModel):
    """Request to create a new IP list.

    Attributes:
        name: List name (must be unique per account)
        kind: Type of list
        description: Optional description
    """

    name: str = Field(description="List name (must be unique)")
    kind: ListKind = Field(default=ListKind.IP, description="Type of list")
    description: str | None = Field(default=None, description="Optional description")
