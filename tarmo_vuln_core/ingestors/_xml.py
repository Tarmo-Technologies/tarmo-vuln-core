"""Hardened XML parsing shared by every XML-based ingestor.

All parsing goes through :mod:`defusedxml` with its defaults: entity
declarations, external entities and external DTD references are *refused*
(``EntitiesForbidden`` / ``ExternalReferenceForbidden``) instead of being
expanded or fetched. That blocks "billion laughs" / quadratic-blowup entity
bombs and XXE file/network reads — which matters for an air-gapped consumer
that ingests untrusted tool output.

Every failure is converted to :class:`IngestorError`:

* malformed XML, an encoding declaration pyexpat cannot use (multi-byte
  codecs such as ``shift_jis`` raise ``ValueError``; unknown codec names raise
  ``LookupError``) or I/O errors → ``IngestorError("Failed to parse <fmt> XML ...")``
* forbidden constructs → :class:`UnsafeXmlError` (an ``IngestorError``) whose
  message contains "forbidden".

``can_handle()`` probes call these helpers inside ``try/except IngestorError``
and return ``False``, so a hostile file can never crash auto-detection.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Protocol
from xml.etree.ElementTree import Element, ParseError

import defusedxml.ElementTree as DET
from defusedxml import DefusedXmlException

from tarmo_vuln_core.ingestors.base import IngestorError, UnsafeXmlError

__all__ = ["iterparse_xml", "parse_xml_bytes", "parse_xml_file", "xml_first_tag"]


def _unsafe(fmt: str, source: str, exc: DefusedXmlException) -> UnsafeXmlError:
    return UnsafeXmlError(
        f"Refusing to parse {fmt} XML {source}: {type(exc).__name__} — entity "
        "declarations and external references are forbidden (possible "
        f"entity-expansion or XXE payload): {exc}"
    )


def parse_xml_file(path: Path, *, fmt: str) -> Element:
    """Parse *path* with defusedxml and return the root element.

    Raises:
        UnsafeXmlError: The document declares entities or external references.
        IngestorError: The file cannot be read or is not well-formed XML.
    """
    try:
        root = DET.parse(path).getroot()
    except DefusedXmlException as exc:
        raise _unsafe(fmt, f"'{path.name}'", exc) from exc
    except (ParseError, ValueError, LookupError) as exc:
        raise IngestorError(f"Failed to parse {fmt} XML '{path.name}': {exc}") from exc
    except OSError as exc:
        raise IngestorError(f"Cannot read {fmt} XML '{path}': {exc}") from exc
    if root is None:  # pragma: no cover — ElementTree always yields a root for valid XML
        raise IngestorError(f"Failed to parse {fmt} XML '{path.name}': empty document")
    return root


def parse_xml_bytes(data: bytes | str, *, fmt: str, source: str = "<bytes>") -> Element:
    """Parse an in-memory XML document with defusedxml and return the root element.

    Raises:
        UnsafeXmlError: The document declares entities or external references.
        IngestorError: The data is not well-formed XML.
    """
    try:
        return DET.fromstring(data)
    except DefusedXmlException as exc:
        raise _unsafe(fmt, source, exc) from exc
    except (ParseError, ValueError, LookupError) as exc:
        raise IngestorError(f"Failed to parse {fmt} XML {source}: {exc}") from exc


def xml_first_tag(path: Path, *, fmt: str) -> str:
    """Return the root element's tag by streaming only up to the first start event.

    Cheap probe for large reports. Entity declarations in the internal DTD
    subset precede the root element, so a forbidden construct is still
    detected before any element is returned.

    Raises:
        UnsafeXmlError: The document declares entities or external references.
        IngestorError: The file cannot be read, is malformed, or has no element.
    """
    try:
        for _event, elem in DET.iterparse(str(path), events=("start",)):
            return str(elem.tag)
    except DefusedXmlException as exc:
        raise _unsafe(fmt, f"'{path.name}'", exc) from exc
    except (ParseError, ValueError, LookupError) as exc:
        raise IngestorError(f"Failed to parse {fmt} XML '{path.name}': {exc}") from exc
    except OSError as exc:
        raise IngestorError(f"Cannot read {fmt} XML '{path}': {exc}") from exc
    raise IngestorError(f"Failed to parse {fmt} XML '{path.name}': no root element")


class SupportsReadBytes(Protocol):
    """Minimal binary reader accepted by :func:`iterparse_xml`."""

    def read(self, size: int = ..., /) -> bytes: ...


def iterparse_xml(
    source: SupportsReadBytes, *, fmt: str, label: str, events: tuple[str, ...] = ("start", "end")
) -> Iterator[tuple[str, Element]]:
    """Stream ``(event, element)`` pairs from *source* with defusedxml.

    For large or untrusted documents: the caller processes each element as it
    completes and then clears it, so peak memory stays independent of document
    size instead of materialising the whole tree. Exceptions raised by
    ``source.read()`` itself (e.g. a size-cap :class:`IngestorError`) propagate
    unchanged.

    Raises:
        UnsafeXmlError: The document declares entities or external references.
        IngestorError: The data is malformed or declares an unusable encoding.
    """
    try:
        yield from DET.iterparse(source, events=events)
    except DefusedXmlException as exc:
        raise _unsafe(fmt, label, exc) from exc
    except (ParseError, ValueError, LookupError) as exc:
        raise IngestorError(f"Failed to parse {fmt} XML {label}: {exc}") from exc
