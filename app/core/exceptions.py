class MondooBaseException(Exception):
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code


class InvalidSecretKeyError(MondooBaseException):
    def __init__(self):
        super().__init__(message="Endpoint not found", status_code=404)


class MondooAPIError(MondooBaseException):
    def __init__(self, message: str):
        super().__init__(message=f"Mondoo API Kommunikation fehlgeschlagen: {message}", status_code=502)


class PayloadParsingError(MondooBaseException):
    def __init__(self, message: str):
        super().__init__(message=f"Fehler beim Parsen des Payloads: {message}", status_code=422)


class PaginationLimitExceededError(MondooBaseException):
    def __init__(self, max_pages: int):
        super().__init__(message=f"Paginierungslimit von {max_pages} Seiten überschritten.", status_code=502)

class ServiceNowAPIError(MondooBaseException):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message=f"ServiceNow API Kommunikation fehlgeschlagen: {message}", status_code=status_code)