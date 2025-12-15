"""Tests for cloudflare_api models."""


from cloudflare_api.models import (
    BulkOperation,
    BulkOperationStatus,
    IPList,
    IPListItem,
    IPListItemInput,
    ListKind,
)


class TestListKind:
    """Test suite for ListKind enum."""

    def test_all_kinds_exist(self):
        """Test all expected list kinds are defined."""
        assert ListKind.IP.value == "ip"
        assert ListKind.REDIRECT.value == "redirect"
        assert ListKind.HOSTNAME.value == "hostname"
        assert ListKind.ASN.value == "asn"

    def test_kind_from_string(self):
        """Test creating ListKind from string."""
        assert ListKind("ip") == ListKind.IP
        assert ListKind("redirect") == ListKind.REDIRECT


class TestBulkOperationStatus:
    """Test suite for BulkOperationStatus enum."""

    def test_all_statuses_exist(self):
        """Test all expected statuses are defined."""
        assert BulkOperationStatus.PENDING.value == "pending"
        assert BulkOperationStatus.RUNNING.value == "running"
        assert BulkOperationStatus.COMPLETED.value == "completed"
        assert BulkOperationStatus.FAILED.value == "failed"


class TestIPListItem:
    """Test suite for IPListItem model."""

    def test_create_item_minimal(self):
        """Test creating item with minimal fields."""
        item = IPListItem(ip="192.168.1.1")

        assert item.ip == "192.168.1.1"
        assert item.id is None
        assert item.comment is None

    def test_create_item_full(self):
        """Test creating item with all fields."""
        item = IPListItem(
            id="item-123",
            ip="10.0.0.0/8",
            comment="Private network",
        )

        assert item.id == "item-123"
        assert item.ip == "10.0.0.0/8"
        assert item.comment == "Private network"


class TestIPList:
    """Test suite for IPList model."""

    def test_create_list(self):
        """Test creating IP list model."""
        ip_list = IPList(
            id="list-123",
            name="blocked-ips",
            description="Blocked IP addresses",
            kind=ListKind.IP,
            num_items=10,
        )

        assert ip_list.id == "list-123"
        assert ip_list.name == "blocked-ips"
        assert ip_list.description == "Blocked IP addresses"
        assert ip_list.kind == ListKind.IP
        assert ip_list.num_items == 10

    def test_create_list_defaults(self):
        """Test IP list default values."""
        ip_list = IPList(id="list-123", name="test")

        assert ip_list.description is None
        assert ip_list.kind == ListKind.IP
        assert ip_list.num_items == 0
        assert ip_list.num_referencing_filters == 0


class TestBulkOperation:
    """Test suite for BulkOperation model."""

    def test_create_operation_pending(self):
        """Test creating pending bulk operation."""
        op = BulkOperation(
            id="op-123",
            status=BulkOperationStatus.PENDING,
        )

        assert op.id == "op-123"
        assert op.status == BulkOperationStatus.PENDING
        assert op.error is None

    def test_create_operation_failed(self):
        """Test creating failed bulk operation."""
        op = BulkOperation(
            id="op-123",
            status=BulkOperationStatus.FAILED,
            error="Invalid IP format",
        )

        assert op.status == BulkOperationStatus.FAILED
        assert op.error == "Invalid IP format"


class TestIPListItemInput:
    """Test suite for IPListItemInput model."""

    def test_create_input_minimal(self):
        """Test creating input with minimal fields."""
        input_item = IPListItemInput(ip="1.2.3.4")

        assert input_item.ip == "1.2.3.4"
        assert input_item.comment is None

    def test_create_input_with_comment(self):
        """Test creating input with comment."""
        input_item = IPListItemInput(ip="1.2.3.4", comment="Bad actor")

        assert input_item.ip == "1.2.3.4"
        assert input_item.comment == "Bad actor"

    def test_to_api_dict_minimal(self):
        """Test to_api_dict with minimal fields."""
        input_item = IPListItemInput(ip="1.2.3.4")
        result = input_item.to_api_dict()

        assert result == {"ip": "1.2.3.4"}

    def test_to_api_dict_with_comment(self):
        """Test to_api_dict includes comment when present."""
        input_item = IPListItemInput(ip="1.2.3.4", comment="Test")
        result = input_item.to_api_dict()

        assert result == {"ip": "1.2.3.4", "comment": "Test"}
