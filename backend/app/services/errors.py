"""Domain errors raised by services and mapped to HTTP responses in app.main."""


class DomainError(Exception):
    status_code = 400

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class NotFound(DomainError):
    status_code = 404


class PermissionDenied(DomainError):
    status_code = 403


class ValidationFailed(DomainError):
    status_code = 422


class Busy(DomainError):
    status_code = 503
