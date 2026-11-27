from pipeline.sources.base import Source
from pipeline.sources.cisa_kev import CisaKev
from pipeline.sources.hibp import HibpBreaches
from pipeline.sources.nvd import NvdCves

# Alle aktiven Quellen. Neue Quelle: Klasse anlegen und hier eintragen.
SOURCES: dict[str, Source] = {
    source.name: source
    for source in (HibpBreaches(), CisaKev(), NvdCves())
}
