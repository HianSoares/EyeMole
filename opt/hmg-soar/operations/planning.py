"""One dependency contract for generation, approval and dispatch."""
import threading
from collections import OrderedDict
from pathlib import Path
from remediation.engine import RemediationEngine
from remediation.snapshot import file_signature, revision_of


_LOCK = threading.Lock()
_ENGINES = OrderedDict()
_MAX_ENGINES = 8


def engine_for(config):
    """Engine per source layout. Reusing it is safe: every generation re-checks
    the signature of each source and reloads what changed (stale data is never
    served). Reuse avoids re-reading large snapshots on each status request."""
    kwargs = {'snapshot_path': Path(config.get('snapshot_path', '/var/www/wazuh-soar/data/latest.json')),
              'config_dir': Path(config.get('config_dir', '/opt/hmg-soar/config'))}
    for key in ('grype_snapshot_path', 'evidence_path', 'templates_path'):
        if config.get(key):
            kwargs[key] = Path(config[key])
    key = tuple(sorted((name, str(value)) for name, value in kwargs.items()))
    with _LOCK:
        engine = _ENGINES.get(key)
        if engine is None:
            engine = _ENGINES[key] = RemediationEngine(**kwargs)
            while len(_ENGINES) > _MAX_ENGINES:
                _ENGINES.popitem(last=False)
        else:
            _ENGINES.move_to_end(key)
        return engine


def source_revision(engine):
    return revision_of(file_signature(path) for path in engine.dependency_paths())
