"""One dependency contract for generation, approval and dispatch."""
from pathlib import Path
from remediation.engine import RemediationEngine
from remediation.snapshot import file_signature, revision_of


def engine_for(config):
    kwargs = {'snapshot_path': Path(config.get('snapshot_path', '/var/www/wazuh-soar/data/latest.json')),
              'config_dir': Path(config.get('config_dir', '/opt/hmg-soar/config'))}
    for key in ('grype_snapshot_path', 'evidence_path', 'templates_path'):
        if config.get(key):
            kwargs[key] = Path(config[key])
    return RemediationEngine(**kwargs)


def source_revision(engine):
    return revision_of(file_signature(path) for path in engine.dependency_paths())
