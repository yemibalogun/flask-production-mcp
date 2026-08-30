from __future__ import annotations

from pathlib import Path

from flask_production_mcp.analyzers.database import (
    analyze_database,
    analyze_database_files,
)

from flask_production_mcp.models.findings import Severity, Confidence



def write_python(
    root: Path,
    relative_path: str,
    source: str,
) -> Path:
    """Create a Python source file inside a temporary test project."""

    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def test_detects_sqlalchemy_model(tmp_path: Path) -> None:
    source_file = write_python(
        tmp_path,
        "app/models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True)
""",
    )

    result = analyze_database_files([source_file])

    assert result.sqlalchemy_detected is False
    assert result.flask_sqlalchemy_detected is True

    assert len(result.models) == 1

    model = result.models[0]

    assert model.name == "User"

    assert [column.name for column in model.columns] == [
        "id",
        "email",
    ]

    assert model.columns[0].primary_key is True
    assert model.columns[1].unique is True
    assert model.columns[1].indexed is True


def test_detects_foreign_key(tmp_path: Path) -> None:
    source_file = write_python(
        tmp_path,
        "models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
    )
""",
    )

    result = analyze_database_files([source_file])

    model = result.models[0]
    user_id = next(
        column
        for column in model.columns
        if column.name == "user_id"
    )

    assert user_id.foreign_key == "user.id"
    assert user_id.nullable is False


def test_detects_relationship(tmp_path: Path) -> None:
    source_file = write_python(
        tmp_path,
        "models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orders = db.relationship("Order")
""",
    )

    result = analyze_database_files([source_file])

    model = result.models[0]

    assert len(model.relationships) == 1

    relationship = model.relationships[0]

    assert relationship.model == "User"
    assert relationship.attribute == "orders"
    assert relationship.target == "Order"


def test_detects_raw_sql_without_calling_it(tmp_path: Path) -> None:
    source_file = write_python(
        tmp_path,
        "app/database.py",
        """
from sqlalchemy import text


def get_user(session, user_id):
    return session.execute(
        text("SELECT * FROM users WHERE id = :user_id"),
        {"user_id": user_id},
    )
""",
    )

    result = analyze_database_files([source_file])

    assert len(result.raw_sql) == 1
    assert result.raw_sql[0].line > 0


def test_raw_sql_generates_review_finding(tmp_path: Path) -> None:
    source_file = write_python(
        tmp_path,
        "app/database.py",
        """
def get_user(session, user_id):
    return session.execute(
        "SELECT * FROM users WHERE id = :user_id",
        {"user_id": user_id},
    )
""",
    )

    result = analyze_database(tmp_path, [source_file])

    findings = result["findings"]

    assert any(
        finding.id == "DB-SEC-001"
        for finding in findings
    )


def test_malformed_python_does_not_abort_analysis(
    tmp_path: Path,
) -> None:
    valid_file = write_python(
        tmp_path,
        "models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
""",
    )

    invalid_file = write_python(
        tmp_path,
        "broken.py",
        """
class Broken(
""",
    )

    result = analyze_database_files(
        [valid_file, invalid_file]
    )

    assert len(result.models) == 1
    assert result.models[0].name == "User"

    assert len(result.parse_errors) == 1
    assert result.parse_errors[0]["file"] == str(invalid_file)


def test_recommends_index_for_frequently_filtered_unindexed_column(
    tmp_path: Path,
) -> None:
    write_python(
        tmp_path,
        "models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255))
""",
    )

    write_python(
        tmp_path,
        "routes.py",
        """
from .models import User


def find_user(email):
    return User.query.filter(User.email == email).first()
""",
    )

    result = analyze_database(tmp_path)

    findings = [
        finding
        for finding in result["findings"]
        if finding.id == "DB-PERF-001"
    ]

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "performance"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.MEDIUM

    assert finding.file == str((tmp_path / "routes.py").resolve())

    # The query call is on line 6 because the test source string begins
    # with a newline and contains two blank lines before the function body.
    assert finding.line == 6

    assert finding.metadata["model"] == "User"
    assert finding.metadata["column"] == "email"
    assert finding.metadata["query_operation"] == "filter"
    assert finding.metadata["query"] == (
        "User.query.filter(User.email == email)"
    )
    assert finding.metadata["index_detected"] is False

    assert "index" in finding.title.lower()
    assert "User.email" in finding.description
    assert "index" in finding.recommendation.lower()




def test_does_not_recommend_existing_column_index(
    tmp_path: Path,
) -> None:
    write_python(
        tmp_path,
        "models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(
        db.String(255),
        index=True,
    )
""",
    )

    write_python(
        tmp_path,
        "routes.py",
        """
from .models import User


def find_user(email):
    return User.query.filter(User.email == email).first()
""",
    )

    result = analyze_database(tmp_path)

    assert not any(
        finding["rule_id"] == "DB-PERF-001"
        for finding in result["findings"]
    )

def test_unique_column_does_not_trigger_duplicate_index_recommendation(
    tmp_path: Path,
) -> None:
    write_python(
        tmp_path,
        "models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(
        db.String(255),
        unique=True,
    )
""",
    )

    write_python(
        tmp_path,
        "routes.py",
        """
from .models import User


def find_user(email):
    return User.query.filter(User.email == email).first()
""",
    )

    result = analyze_database(tmp_path)

    assert not any(
        finding["rule_id"] == "DB-PERF-001"
        for finding in result["findings"]
    )

def test_composite_index_covers_filtered_column(
    tmp_path: Path,
) -> None:
    write_python(
        tmp_path,
        "models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer)
    status = db.Column(db.String(50))

    __table_args__ = (
        db.Index(
            "ix_order_customer_status",
            "customer_id",
            "status",
        ),
    )
""",
    )

    write_python(
        tmp_path,
        "routes.py",
        """
from .models import Order


def orders(customer_id):
    return Order.query.filter(
        Order.customer_id == customer_id
    ).all()
""",
    )

    result = analyze_database(tmp_path)

    assert not any(
        finding["rule_id"] == "DB-PERF-001"
        for finding in result["findings"]
    )


def test_detects_potential_n_plus_one_relationship_access(
    tmp_path: Path,
) -> None:
    write_python(
        tmp_path,
        "models.py",
        """
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    orders = db.relationship("Order")


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
""",
    )

    write_python(
        tmp_path,
        "routes.py",
        """
from .models import User


def get_users():
    users = User.query.all()

    for user in users:
        print(user.orders)

    return users
""",
    )

    result = analyze_database(tmp_path)

    findings = [
        finding
        for finding in result["findings"]
        if finding.id == "DB-PERF-002"
    ]

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "performance"
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.MEDIUM

    assert finding.file == str((tmp_path / "routes.py").resolve())

    assert finding.metadata["model"] == "User"
    assert finding.metadata["relationship"] == "orders"
    assert finding.metadata["query_operation"] == "all"

    assert "N+1" in finding.title
    assert "eager" in finding.recommendation.lower()
