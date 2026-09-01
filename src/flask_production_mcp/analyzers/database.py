from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from flask_production_mcp.analyzers.exclusions import iter_python_files
from flask_production_mcp.models.findings import Confidence, Finding, Severity


# ---------------------------------------------------------------------------
# Database-analysis data structures
# ---------------------------------------------------------------------------
#
# These structures deliberately contain FACTS discovered from the source
# code.  They are not findings themselves.
#
# This separation is important because later optimization/security rules
# should reason over a normalized representation rather than repeatedly
# walking the AST and making assumptions about a project's structure.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DatabaseColumn:
    """A database column discovered from a model declaration."""

    name: str
    file: Path
    line: int
    type_name: str | None = None
    primary_key: bool = False
    nullable: bool | None = None
    unique: bool = False
    indexed: bool = False
    foreign_key: str | None = None


@dataclass(slots=True)
class DatabaseRelationship:
    """A relationship discovered from a SQLAlchemy model."""

    model: str
    attribute: str
    target: str | None
    file: Path
    line: int
    relationship_type: str = "unknown"

@dataclass(slots=True)
class DatabaseIndex:
    """An index discovered on a database model."""

    model: str
    columns: list[str]

    # True when the index is declared as unique.
    unique: bool = False

    file: Path | None = None
    line: int | None = None

@dataclass(slots=True)
class DatabaseQuery:
    """A database query discovered from application source."""

    file: Path
    line: int
    operation: str
    expression: str

    # SQLAlchemy model involved in the query, when statically identifiable.
    model: str | None = None

    # Columns used in filter predicates, represented as Model.column.
    filter_columns: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DatabaseModel:
    """Database model discovered from Python source."""

    name: str
    table_name: str | None = None
    file: Path | None = None
    line: int | None = None

    columns: list[DatabaseColumn] = field(default_factory=list)
    foreign_keys: list[str] = field(default_factory=list)
    relationships: list[DatabaseRelationship] = field(default_factory=list)
    indexes: list[DatabaseIndex] = field(default_factory=list)


@dataclass(slots=True)
class RawSQLUsage:
    """A potentially significant raw-SQL usage site."""

    file: Path
    line: int
    function: str | None
    expression: str


@dataclass(slots=True)
class DatabaseAnalysis:
    """
    Normalized database architecture discovered from a Flask project.

    This representation is intentionally framework/domain agnostic.
    """

    models: list[DatabaseModel] = field(default_factory=list)

    # Database queries discovered from application source. These are facts,
    # not findings; performance rules interpret them later.
    queries: list[DatabaseQuery] = field(default_factory=list)

    raw_sql: list[RawSQLUsage] = field(default_factory=list)

    # Database-related imports provide useful context for determining which
    # AST constructs are actually database-oriented.
    sqlalchemy_detected: bool = False
    flask_sqlalchemy_detected: bool = False

    # Files that could not be parsed are retained so callers can understand
    # why the analysis may be incomplete.
    parse_errors: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _attribute_name(node: ast.AST) -> str | None:
    """
    Return the final attribute/name component of an AST expression.

    Examples:
        Column              -> "Column"
        db.Column           -> "Column"
        sqlalchemy.Column  -> "Column"
        relationship        -> "relationship"
        db.relationship    -> "relationship"

    Returning only the final component allows the analyzer to recognize
    common SQLAlchemy patterns without depending on one import style.
    """

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        return node.attr

    return None


def _call_name(node: ast.Call) -> str | None:
    """Return the callable name from a function call."""

    return _attribute_name(node.func)


def _string_value(node: ast.AST) -> str | None:
    """
    Safely extract a statically-known string.

    Dynamic expressions are intentionally ignored.  A static analyzer should
    not pretend it knows the value of something such as:

        url_prefix = os.getenv("PREFIX")
    """

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    return None


def _keyword_value(
    call: ast.Call,
    name: str,
) -> ast.AST | None:
    """Return the AST value of a named keyword argument."""

    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value

    return None


def _boolean_keyword(
    call: ast.Call,
    name: str,
) -> bool | None:
    """Extract a statically-known boolean keyword argument."""

    value = _keyword_value(call, name)

    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return value.value

    return None


def _is_sqlalchemy_column_call(node: ast.AST) -> bool:
    """
    Determine whether an AST node resembles a SQLAlchemy Column declaration.

    Supports common forms such as:

        Column(...)
        db.Column(...)
        sqlalchemy.Column(...)

    We intentionally do not require an exact import path because Flask
    projects frequently expose SQLAlchemy through application extensions.
    """

    return (
        isinstance(node, ast.Call)
        and _call_name(node) in {"Column", "mapped_column"}
    )


def _is_relationship_call(node: ast.AST) -> bool:
    """Determine whether an AST node resembles a SQLAlchemy relationship."""

    return (
        isinstance(node, ast.Call)
        and _call_name(node) == "relationship"
    )


def _extract_type_name(call: ast.Call) -> str | None:
    """
    Extract the apparent SQLAlchemy column type.

    Example:

        Column(String(255))
        Column(db.String(255))
        mapped_column(Integer)

    For ``String(255)`` the result is ``String``.
    """

    if not call.args:
        return None

    first = call.args[0]

    if isinstance(first, ast.Call):
        return _call_name(first)

    return _attribute_name(first)


def _extract_foreign_key(call: ast.Call) -> str | None:
    """Extract a statically-known ForeignKey target from Column arguments."""

    for argument in call.args:
        if not isinstance(argument, ast.Call):
            continue

        if _call_name(argument) != "ForeignKey":
            continue

        if not argument.args:
            continue

        return _string_value(argument.args[0])

    return None


def _has_column_modifier(
    call: ast.Call,
    modifier: str,
) -> bool:
    """
    Determine whether a Column contains a modifier.

    Handles common forms such as:

        Column(String, unique=True)
        Column(String, index=True)
        Column(String, primary_key=True)

    and:

        Column(String, db.UniqueConstraint(...))

    The initial implementation deliberately focuses on direct, statically
    visible declarations.  More advanced constraint resolution can be added
    later without changing the public analyzer contract.
    """

    value = _boolean_keyword(call, modifier)

    return value is True


# ---------------------------------------------------------------------------
# Model extraction
# ---------------------------------------------------------------------------


def _extract_model(
    node: ast.ClassDef,
    file_path: Path,
) -> DatabaseModel | None:
    """
    Extract a SQLAlchemy model from a class declaration.

    We recognize the common patterns:

        class User(db.Model):
            ...

        class User(Base):
            ...

        class User(BaseModel):
            ...

    A class is considered a database model when one of its bases resembles
    a SQLAlchemy declarative base/model.

    This is intentionally heuristic because static analysis cannot safely
    import and execute arbitrary application code.
    """

    base_names = {
        name
        for base in node.bases
        if (name := _attribute_name(base))
    }

    sqlalchemy_base_signals = {
        "Model",
        "Base",
        "DeclarativeBase",
    }

    if not base_names.intersection(sqlalchemy_base_signals):
        return None

    model = DatabaseModel(
        name=node.name,
        file=file_path,
        line=node.lineno,
    )

    for child in node.body:
        if not isinstance(child, ast.Assign):
            continue

        # Only simple class attributes can be confidently associated with a
        # database column from static source.
        if len(child.targets) != 1:
            continue

        target = child.targets[0]

        if not isinstance(target, ast.Name):
            continue

        if not isinstance(child.value, ast.Call):
            continue

        if _is_sqlalchemy_column_call(child.value):
            column = DatabaseColumn(
                name=target.id,
                file=file_path,
                line=child.lineno,
                type_name=_extract_type_name(child.value),
                primary_key=_has_column_modifier(
                    child.value,
                    "primary_key",
                ),
                nullable=_boolean_keyword(
                    child.value,
                    "nullable",
                ),
                unique=_has_column_modifier(
                    child.value,
                    "unique",
                ),
                indexed=_has_column_modifier(
                    child.value,
                    "index",
                ),
                foreign_key=_extract_foreign_key(child.value),
            )

            model.columns.append(column)

        elif _is_relationship_call(child.value):
            target_model = _string_value(child.value.args[0]) if child.value.args else None

            model.relationships.append(
                DatabaseRelationship(
                    model=node.name,
                    attribute=target.id,
                    target=target_model,
                    file=file_path,
                    line=child.lineno,
                )
            )

    return model


# ---------------------------------------------------------------------------
# Raw SQL detection
# ---------------------------------------------------------------------------


RAW_SQL_CALL_NAMES = frozenset(
    {
        "execute",
        "executemany",
        "exec_driver_sql",
    }
)


def _detect_raw_sql(
    tree: ast.AST,
    file_path: Path,
) -> list[RawSQLUsage]:
    """
    Detect potentially significant raw SQL execution.

    This does NOT immediately declare SQL injection.

    For example:

        db.session.execute(text("SELECT ..."))

    may be perfectly safe.

    The first phase records the usage so later analysis can determine whether
    the SQL is static, parameterized, dynamically constructed, or potentially
    influenced by user input.
    """

    usages: list[RawSQLUsage] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if _call_name(node) not in RAW_SQL_CALL_NAMES:
            continue

        expression = ast.unparse(node)

        function_name: str | None = None

        parent = None

        # Parent links are not present in Python's AST by default.  We don't
        # attempt to reconstruct them here; a later analysis pass can attach
        # function ownership when we introduce a project-wide AST index.
        del parent

        usages.append(
            RawSQLUsage(
                file=file_path,
                line=node.lineno,
                function=function_name,
                expression=expression,
            )
        )

    return usages


def _extract_model_from_query(node: ast.Call) -> str | None:
    """
    Extract a SQLAlchemy model name from a query expression.

    Recognizes patterns such as:

        User.query.filter(...)
        User.query.filter_by(...)
        User.query.first()

    The function intentionally returns None when the model cannot be
    determined statically.
    """

    current: ast.AST = node

    # Walk backwards through chained Attribute/Call nodes until we reach
    # something resembling `Model.query`.
    while isinstance(current, ast.Call):
        current = current.func

    while isinstance(current, ast.Attribute):
        if current.attr == "query":
            owner = current.value

            if isinstance(owner, ast.Name):
                return owner.id

            if isinstance(owner, ast.Attribute):
                return owner.attr

        current = current.value

    return None


def _extract_filter_columns(node: ast.AST) -> list[str]:
    """
    Extract Model.column references from a SQLAlchemy filter expression.

    Example:

        User.email == email

    becomes:

        ["User.email"]

    Only statically identifiable model-column references are returned.
    """

    columns: list[str] = []

    for child in ast.walk(node):
        if not isinstance(child, ast.Attribute):
            continue

        if not isinstance(child.value, ast.Name):
            continue

        # Avoid treating arbitrary attributes as database columns. The
        # strongest static signal available here is the Model.column form.
        columns.append(f"{child.value.id}.{child.attr}")

    return list(dict.fromkeys(columns))


def _detect_database_queries(
    tree: ast.AST,
    file_path: Path,
) -> list[DatabaseQuery]:
    """
    Detect SQLAlchemy ORM query operations from static Python source.

    Supported patterns include:

        User.query.filter(User.email == email)
        User.query.filter_by(email=email)
        User.query.first()
        User.query.all()

    The analyzer never imports or executes the target application.

    A query is only recorded when the AST provides enough evidence to
    associate it with a model. This prevents unrelated methods such as:

        items.filter(...)

    from being incorrectly classified as database queries.
    """

    queries: list[DatabaseQuery] = []

    query_operations = {
        "filter",
        "filter_by",
        "first",
        "one",
        "one_or_none",
        "all",
        "count",
        "paginate",
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        operation = _call_name(node)

        if operation not in query_operations:
            continue

        model: str | None = None

        # ---------------------------------------------------------------
        # Resolve the model from the complete chained expression.
        #
        # For:
        #
        #     User.query.filter(...)
        #
        # the AST for this Call has:
        #
        #     node.func -> Attribute("filter")
        #     node.func.value -> Attribute("query")
        #     node.func.value.value -> Name("User")
        #
        # We specifically look for the `.query` attribute instead of
        # assuming that every method called `filter()` is SQLAlchemy.
        # ---------------------------------------------------------------
        current: ast.AST = node.func

        while isinstance(current, ast.Attribute):
            if current.attr == "query":
                query_owner = current.value

                if isinstance(query_owner, ast.Name):
                    model = query_owner.id

                elif isinstance(query_owner, ast.Attribute):
                    model = query_owner.attr

                break

            current = current.value

        if model is None:
            continue

        filter_columns: list[str] = []

        # ---------------------------------------------------------------
        # Extract model-column references from filter expressions.
        #
        # For:
        #
        #     User.email == email
        #
        # this produces:
        #
        #     ["User.email"]
        #
        # We only accept Attribute(Name, attribute) forms because they give
        # us a statically identifiable `Model.column` reference.
        # ---------------------------------------------------------------
        if operation == "filter":
            for argument in node.args:
                for child in ast.walk(argument):
                    if not isinstance(child, ast.Attribute):
                        continue

                    if not isinstance(child.value, ast.Name):
                        continue

                    # Only associate the column with the current query model.
                    # This prevents unrelated objects appearing in a complex
                    # filter expression from being treated as columns on the
                    # queried model.
                    if child.value.id != model:
                        continue

                    column_reference = f"{model}.{child.attr}"

                    if column_reference not in filter_columns:
                        filter_columns.append(column_reference)

        elif operation == "filter_by":
            # `filter_by(email=value)` does not use Model.email in the AST.
            # Instead, the keyword name itself identifies the column.
            for keyword in node.keywords:
                if keyword.arg is not None:
                    filter_columns.append(
                        f"{model}.{keyword.arg}"
                    )

        queries.append(
            DatabaseQuery(
                file=file_path,
                line=node.lineno,
                operation=operation,
                expression=ast.unparse(node),
                model=model,
                filter_columns=filter_columns,
            )
        )

    return queries

# ---------------------------------------------------------------------------
# File analysis
# ---------------------------------------------------------------------------


def analyze_database_files(
    python_files: Iterable[Path],
) -> DatabaseAnalysis:
    """
    Build a project-wide database architecture representation.

    The analyzer processes every supplied Python file independently.
    A failure to parse one file is recorded and does not prevent analysis
    of the remaining project.

    The target project is never imported or executed.
    """

    analysis = DatabaseAnalysis()

    for file_path in python_files:
        file_path = Path(file_path)

        try:
            source = file_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )

            tree = ast.parse(
                source,
                filename=str(file_path),
            )

        except (OSError, SyntaxError) as exc:
            # A malformed or unreadable file must not abort analysis of the
            # entire Flask project.
            analysis.parse_errors.append(
                {
                    "file": str(file_path),
                    "error": str(exc),
                }
            )
            continue

        # ---------------------------------------------------------------
        # Detect database-related imports.
        # ---------------------------------------------------------------

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]

                    if root == "sqlalchemy":
                        analysis.sqlalchemy_detected = True

            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue

                root = node.module.split(".", 1)[0]

                if root == "sqlalchemy":
                    analysis.sqlalchemy_detected = True

                if node.module == "flask_sqlalchemy":
                    analysis.flask_sqlalchemy_detected = True

        # ---------------------------------------------------------------
        # Detect SQLAlchemy models.
        # ---------------------------------------------------------------

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            model = _extract_model(
                node,
                file_path,
            )

            if model is None:
                continue

            # Index declarations belong to the model, so extract them at
            # the same time that we construct the model representation.
            model.indexes.extend(
                _extract_table_indexes(
                    node,
                    file_path,
                )
            )

            analysis.models.append(model)

        # ---------------------------------------------------------------
        # Detect ORM queries.
        #
        # This is deliberately independent of model discovery. A Flask
        # application can define models and queries in completely different
        # modules, so both must be collected project-wide before the finding
        # phase compares them.
        # ---------------------------------------------------------------

        analysis.queries.extend(
            _detect_database_queries(
                tree,
                file_path,
            )
        )

        # ---------------------------------------------------------------
        # Detect raw SQL execution.
        #
        # Detection does not mean vulnerability. The later security rules
        # determine whether the SQL construction is actually suspicious.
        # ---------------------------------------------------------------

        analysis.raw_sql.extend(
            _detect_raw_sql(
                tree,
                file_path,
            )
        )

    return analysis


# ---------------------------------------------------------------------------
# Database findings
# ---------------------------------------------------------------------------


def _build_database_findings(
    analysis: DatabaseAnalysis,
) -> list[Finding]:
    """
    Convert normalized database facts into actionable findings.

    Phase 1 intentionally contains only high-confidence checks.  We should
    not generate speculative "missing index" findings before we understand
    which columns are actually queried by the application.
    """

    findings: list[Finding] = []

    # ---------------------------------------------------------------
    # Raw SQL review
    # ---------------------------------------------------------------
    #
    # Raw SQL itself is not a vulnerability.  The important distinction is
    # whether the SQL is dynamically constructed from untrusted data.
    #
    # Therefore the initial finding is informational/low confidence rather
    # than falsely reporting SQL injection.
    # ---------------------------------------------------------------

    for usage in analysis.raw_sql:
        findings.append(
            Finding(
                id="DB-SEC-001",
                category="database",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title="Raw SQL execution detected",
                description=(
                    "The project executes database statements through a "
                    "raw execution API. Raw SQL can be appropriate, but "
                    "dynamically constructed statements require careful "
                    "parameterization to prevent SQL injection."
                ),
                recommendation=(
                    "Prefer parameterized queries or SQLAlchemy expression "
                    "constructs. If raw SQL is required, ensure all "
                    "user-controlled values are passed as bound parameters "
                    "rather than interpolated into the SQL string."
                ),
                file=str(usage.file),
                line=usage.line,
                metadata={
                    "expression": usage.expression,
                    "requires_dynamic_sql_review": True,
                },
            )
        )

    # ---------------------------------------------------------------
    # Query/index performance analysis
    # ---------------------------------------------------------------
    #
    # This compares application query predicates against the indexes
    # discovered on the corresponding models. It is deliberately a
    # recommendation rather than a guaranteed performance defect because
    # static analysis cannot observe production cardinality or workload.
    findings.extend(
        Finding(
            id=finding.rule_id,
            category=finding.category,
            severity=Severity(finding.severity),
            confidence=Confidence.MEDIUM,
            title=finding.title,
            description=finding.description,
            recommendation=finding.recommendation,
            file=finding.file,
            line=finding.line,
            metadata=finding.evidence,
        )
        for finding in _detect_missing_indexes(
            analysis.models,
            analysis.queries,
        )
    )

    return findings


def analyze_database(
    project_root: Path,
    python_files: Iterable[Path] | None = None,
) -> dict[str, Any]:
    """
    Analyze database architecture, performance, and security characteristics.

    The analyzer performs static inspection only. It never imports or
    executes the target Flask application.

    Results include:

    - normalized SQLAlchemy model information
    - relationships and foreign keys
    - declared indexes
    - detected query patterns
    - raw SQL usage
    - potential performance issues
    - potential security issues
    - parse errors encountered during analysis
    """

    root = Path(project_root).resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(
            f"Database analysis root does not exist or is not a directory: {root}"
        )

    if python_files is None:
        python_files = iter_python_files(root)

    files = [
        Path(path)
        for path in python_files
        if Path(path).is_file()
    ]

    # Run the normalized architecture analysis first. This gives all
    # subsequent rules a consistent representation of the project.
    analysis = analyze_database_files(files)

    findings = _build_database_findings(analysis)

    # N+1 detection requires both model relationship information and the
    # source files containing the query/loop usage.
    findings.extend(
        _detect_potential_n_plus_one(
            files,
            analysis.models,
        )
    )

    return {
        "success": True,
        "models": analysis.models,
        "queries": analysis.queries,
        "raw_sql": analysis.raw_sql,
        "sqlalchemy_detected": analysis.sqlalchemy_detected,
        "flask_sqlalchemy_detected": analysis.flask_sqlalchemy_detected,
        "parse_errors": analysis.parse_errors,
        "findings": findings,
    }



def _keyword_bool(
    node: ast.Call,
    name: str,
) -> bool:
    """Return the statically known boolean value of a keyword argument."""

    for keyword in node.keywords:
        if keyword.arg != name:
            continue

        if isinstance(keyword.value, ast.Constant):
            return keyword.value.value is True

    return False

def _extract_table_indexes(
    class_node: ast.ClassDef,
    file_path: Path,
) -> list[DatabaseIndex]:
    """Extract statically declared SQLAlchemy Index objects."""

    indexes: list[DatabaseIndex] = []

    for node in class_node.body:
        if not isinstance(node, ast.Assign):
            continue

        if not any(
            isinstance(target, ast.Name)
            and target.id == "__table_args__"
            for target in node.targets
        ):
            continue

        for child in ast.walk(node.value):
            if not isinstance(child, ast.Call):
                continue

            if _call_name(child) != "Index":
                continue

            # Index(name, column1, column2, ...)
            if not child.args:
                continue

            name_node = child.args[0]

            if not isinstance(name_node, ast.Constant):
                continue

            index_name = str(name_node.value)

            columns: list[str] = []

            for argument in child.args[1:]:
                if isinstance(argument, ast.Constant):
                    columns.append(str(argument.value))
                elif isinstance(argument, ast.Name):
                    columns.append(argument.id)
                elif isinstance(argument, ast.Attribute):
                    columns.append(argument.attr)

            if columns:
                indexes.append(
                    DatabaseIndex(
                        model=class_node.name,
                        columns=columns,
                        unique=False,
                        file=file_path,
                        line=child.lineno,
                    )
                )

    return indexes

@dataclass(slots=True)
class DatabaseFinding:
    """Actionable database design finding."""

    rule_id: str
    category: str
    severity: str
    title: str
    description: str
    recommendation: str

    file: str | None = None
    line: int | None = None

    evidence: dict[str, Any] = field(default_factory=dict)


def _index_exists_for_column(
    model: DatabaseModel,
    column: str,
) -> bool:
    """Determine whether an existing index covers the requested column."""

    for index in model.indexes:
        if column in index.columns:
            return True

    for column_info in model.columns:
        if column_info.name != column:
            continue

        # SQLAlchemy's index=True creates a supporting index.
        if column_info.indexed:
            return True

        # A unique constraint generally creates a uniqueness index/constraint,
        # so recommending another ordinary index would often be redundant.
        if column_info.unique:
            return True

    return False


def _detect_missing_indexes(
    models: list[DatabaseModel],
    queries: list[DatabaseQuery],
) -> list[DatabaseFinding]:
    """
    Find query predicates that appear to lack supporting indexes.

    This is deliberately a recommendation rather than a hard error.
    Static analysis cannot know table cardinality, query frequency,
    planner statistics, or production workload.
    """

    findings: list[DatabaseFinding] = []

    models_by_name = {
        model.name: model
        for model in models
    }

    seen: set[tuple[str, str]] = set()

    for query in queries:
        for qualified_column in query.filter_columns:
            try:
                model_name, column_name = qualified_column.split(".", 1)
            except ValueError:
                continue

            model = models_by_name.get(model_name)

            if model is None:
                continue

            key = (model_name, column_name)

            # Avoid producing the same recommendation repeatedly when a
            # column is queried from multiple locations.
            if key in seen:
                continue

            seen.add(key)

            if _index_exists_for_column(model, column_name):
                continue

            findings.append(
                DatabaseFinding(
                    rule_id="DB-PERF-001",
                    category="performance",
                    severity="medium",
                    title=f"Potential missing index on {model_name}.{column_name}",
                    description=(
                        f"{model_name}.{column_name} is used in a query "
                        "filter, but no supporting index was detected."
                    ),
                    recommendation=(
                        f"Consider adding an index to "
                        f"{model_name}.{column_name} if this lookup is "
                        "performance-sensitive and the column has "
                        "sufficient selectivity."
                    ),
                    file=str(query.file.resolve()),
                    line=query.line,
                    evidence={
                        "model": model_name,
                        "column": column_name,
                        "query_operation": query.operation,
                        "query": query.expression,
                        "index_detected": False,
                    },
                )
            )

    return findings


def _relationship_names_by_model(
    models: list[DatabaseModel],
) -> dict[str, set[str]]:
    """
    Build a lookup of relationship attributes declared on each model.

    Example:

        class User(db.Model):
            orders = db.relationship("Order")

    becomes:

        {
            "User": {"orders"},
        }

    Keeping this as a normalized lookup means the N+1 detector does not need
    to repeatedly inspect the model AST representation.
    """

    relationships_by_model: dict[str, set[str]] = {}

    for model in models:
        relationship_names: set[str] = set()

        for relationship in model.relationships:
            if isinstance(relationship, DatabaseRelationship):
                relationship_names.add(relationship.attribute)
                continue

            # Defensive compatibility for projects/tests that may still carry
            # relationship facts as dictionaries.
            if isinstance(relationship, dict):
                attribute = relationship.get("attribute")

                if isinstance(attribute, str):
                    relationship_names.add(attribute)

        if relationship_names:
            relationships_by_model[model.name] = relationship_names

    return relationships_by_model

def _extract_collection_query_model(node: ast.Call) -> str | None:
    """Return the SQLAlchemy model producing a collection query.

    Examples:
        User.query.all() -> "User"
        User.query.filter(...).all() -> "User"
        User.query.options(...).all() -> "User"

    Returns None when the query origin cannot be identified statically.
    """

    if _call_name(node) not in {"all", "scalars"}:
        return None

    current: ast.AST = node.func

    # Walk backwards through Attribute/Call nodes until the originating
    # `Model.query` attribute is reached.
    while True:
        if isinstance(current, ast.Attribute):
            if (
                current.attr == "query"
                and isinstance(current.value, ast.Name)
            ):
                return current.value.id

            current = current.value
            continue

        if isinstance(current, ast.Call):
            current = current.func
            continue

        break

    return None


def _detect_potential_n_plus_one(
    python_files: Iterable[Path],
    models: list[DatabaseModel],
) -> list[Finding]:
    """
    Detect likely N+1 relationship-access patterns.

    The detector intentionally reports these as potential problems rather
    than guaranteed N+1 queries because static analysis cannot determine the
    runtime loading strategy with absolute certainty.

    Pattern detected:

        users = User.query.all()

        for user in users:
            user.orders

    When ``orders`` is a declared SQLAlchemy relationship on ``User``, the
    relationship may be lazily loaded once per user, producing an N+1 query
    pattern.

    This detector does not execute application code and does not assume that
    every relationship access is inefficient.
    """

    findings: list[Finding] = []

    relationships_by_model = _relationship_names_by_model(models)

    if not relationships_by_model:
        return findings

    for file_path in python_files:
        try:
            source = file_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
            tree = ast.parse(
                source,
                filename=str(file_path),
            )
        except (OSError, SyntaxError):
            # Parsing failures are already represented by the main analysis
            # pass. This secondary detector should never abort the analysis.
            continue

        # Map local variables to the SQLAlchemy model returned by a query.
        #
        # Example:
        #
        #     users = User.query.all()
        #
        # gives:
        #
        #     users -> User
        #
        # This lets us later understand that:
        #
        #     for user in users:
        #
        # refers to a User model instance.
        query_collections: dict[str, tuple[str, str]] = {}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue

            if len(node.targets) != 1:
                continue

            target = node.targets[0]

            if not isinstance(target, ast.Name):
                continue

            if not isinstance(node.value, ast.Call):
                continue

            model_name = _extract_collection_query_model(node.value)

            if (
                model_name is not None
                and model_name in relationships_by_model
            ):
                query_collections[target.id] = (model_name, _call_name(node.value) or "")

        if not query_collections:
            continue

        # Inspect loops because a relationship access inside a loop over a
        # database result is the strongest static signal for N+1 behavior.
        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.AsyncFor)):
                continue

            if not isinstance(node.target, ast.Name):
                continue

            iterator = node.iter

            if not isinstance(iterator, ast.Name):
                continue

            query_info = query_collections.get(iterator.id)

            if query_info is None:
                continue

            model_name, query_operation = query_info

            relationship_names = relationships_by_model.get(
                model_name,
                set(),
            )

            if not relationship_names:
                continue

            loop_variable = node.target.id

            for nested_node in ast.walk(node):
                if not isinstance(nested_node, ast.Attribute):
                    continue

                if not isinstance(nested_node.value, ast.Name):
                    continue

                if nested_node.value.id != loop_variable:
                    continue

                relationship_name = nested_node.attr

                if relationship_name not in relationship_names:
                    continue

                findings.append(
                    Finding(
                        id="DB-PERF-002",
                        category="performance",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        title=(
                            "Potential N+1 relationship query "
                            f"on {model_name}.{relationship_name}"
                        ),
                        description=(
                            f"The {model_name} collection is loaded before "
                            f"a loop that accesses the relationship "
                            f"{model_name}.{relationship_name}. If the "
                            "relationship uses lazy loading, this can issue "
                            "one additional query per parent record."
                        ),
                        recommendation=(
                            "Consider eager-loading the relationship when "
                            "the collection is queried. SQLAlchemy "
                            "selectinload() is often appropriate for "
                            "collections, while joinedload() can be "
                            "appropriate depending on the relationship and "
                            "result shape. Confirm the generated SQL and "
                            "workload before changing the loading strategy."
                        ),
                        file=str(file_path.resolve()),
                        line=nested_node.lineno,
                        metadata={
                            "model": model_name,
                            "relationship": relationship_name,
                            "collection_variable": iterator.id,
                            "loop_variable": loop_variable,
                            "query_operation": query_operation,
                            "detection": "query_result_relationship_access",
                            "requires_runtime_confirmation": True,
                        },
                    )
                )

    return findings


