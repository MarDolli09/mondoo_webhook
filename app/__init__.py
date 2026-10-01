"""Mondoo-zu-ServiceNow-Webhook.

Paketstruktur und Importregeln:

* ``app.api``, ``app.services.mondoo``, ``app.services.parsing``,
  ``app.services.processing`` und ``app.services.servicenow`` sind
  Teilsysteme. Von aussen werden sie ausschliesslich ueber ihre
  ``__init__.py`` angesprochen.
* Konfiguration: Die Teilsysteme unter ``app.services`` lesen weder
  ``settings`` noch ``master_data``; ``app.api.dependencies`` reicht ihnen die
  Werte als Konfigurationsobjekte.
* ``app.core``, ``app.domain`` und ``app.models`` sind Basispakete aus
  eigenstaendigen Modulen. Jedes Modul legt seine Schnittstelle ueber
  ``__all__`` fest; die ``__init__.py`` exportiert nichts.
* Abhaengigkeiten zeigen nur nach unten:
  api -> services -> domain/models -> core.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
