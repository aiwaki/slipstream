"""Packaged workflow contracts: temporary evidence and an inert shell condition."""
import json
import os
from pathlib import Path
import re
import subprocess
import textwrap

import pytest

REPO = Path(__file__).resolve().parents[1]
RELATIVE = '.github/workflows/packaged-update-commit-qualification.yml'
SOURCE = (REPO / RELATIVE).read_text()


def test_same_ten_inputs_readonly_permissions_and_action_pins():
    inputs = SOURCE.split('on:\n',1)[1].split('jobs:\n',1)[0]
    assert re.findall(r'^      ([a-z_]+):$', inputs, re.M) == [
        'old_run_id', 'old_run_attempt', 'old_source_sha', 'old_manifest_sha',
        'new_run_id', 'new_run_attempt', 'new_source_sha', 'new_manifest_sha',
        'root_gate_run_id', 'root_gate_attempt']
    actions = re.findall(r'uses: (\S+)', SOURCE)
    assert [value.split('@')[0] for value in actions] == [
        'actions/checkout', 'actions/setup-python', 'actions/download-artifact',
        'actions/download-artifact', 'actions/download-artifact', 'actions/checkout',
        'actions/upload-artifact']
    assert all(re.fullmatch(r'actions/[a-z-]+@[0-9a-f]{40}', value) for value in actions)
    assert SOURCE.count('persist-credentials: false') == 2
    assert 'permissions:\n  contents: read\n  actions: read\n  attestations: read' in SOURCE
    assert 'if: github.ref == \'refs/heads/main\'' in SOURCE


def test_two_isolated_hosted_cases_no_failfast_or_shared_runtime():
    assert 'runs-on: macos-15\n    timeout-minutes: 60\n    strategy:\n      fail-fast: false\n      matrix:\n        mode: [commit, kill-successor-before-ack]' in SOURCE
    assert 'continue-on-error' not in SOURCE and 'self-hosted' not in SOURCE
    # All install/driver paths remain scoped to each hosted job's RUNNER_TEMP.
    assert SOURCE.count('scripts/qualify_packaged_update_commit.py') == 1
    assert '--mode "$CASE_MODE"' in SOURCE
    assert 'CASE_MODE: ${{ matrix.mode }}' in SOURCE
    assert 'OUTCOME_MODE: ${{ matrix.mode }}' in SOURCE
    assert 'name: packaged-update-${{ matrix.mode }}-${{ github.run_id }}-${{ github.run_attempt }}' in SOURCE


def test_source_proof_precedes_dependencies_and_all_candidate_handling():
    assert 'fetch-depth: 64' in SOURCE
    preflight = SOURCE.index('id: source_preflight')
    assert SOURCE.index('id: checkout') < preflight < SOURCE.index('id: python')
    for step in ('dependencies', 'old_download', 'new_download', 'materialize', 'trigger', 'qualify'):
        assert preflight < SOURCE.index('id: ' + step)
    assert 'CANDIDATE_NEW_SOURCE: ${{ inputs.new_source_sha }}' in SOURCE
    assert '--candidate-source "$CANDIDATE_NEW_SOURCE"' in SOURCE
    assert '${{ runner.temp }}/app-observer-source.json' in SOURCE
    assert 'OUTCOME_SOURCE_PREFLIGHT: ${{ steps.source_preflight.outcome }}' in SOURCE


def test_existing_candidate_authentication_and_old_source_build_commands_unchanged():
    start='      - name: Authenticate pins and unpack exact candidates\n'
    end='      - name: Observe '
    authentication = SOURCE.split(start,1)[1].split(end,1)[0]
    for side in ('old', 'new'):
        for field in ('run_id', 'run_attempt', 'source_sha', 'manifest_sha'):
            assert f'{side.upper()}_{field.upper()}: ${{{{ inputs.{side}_{field} }}}}' in authentication
    assert 'scripts/materialize_pair.py' in authentication
    assert 'native-root-update-*-${{ inputs.root_gate_run_id }}-${{ inputs.root_gate_attempt }}' in authentication
    assert 'ref: ${{ inputs.old_source_sha }}' in authentication
    assert 'scripts/build_packaged_update_trigger.py' in authentication
    assert '--old-source "$GITHUB_WORKSPACE/old-source"' in authentication
    assert '--pair-manifest "$RUNNER_TEMP/app-update/pair.json"' in authentication
    assert authentication.index('scripts/materialize_pair.py') < authentication.index('id: root_gate_download')
    assert authentication.index('id: root_gate_download') < authentication.index('id: old_source')
    assert authentication.index('id: old_source') < authentication.index('scripts/build_packaged_update_trigger.py')
    assert 'if-no-files-found: error' in SOURCE
    assert '${{ runner.temp }}/packaged-commit-result.json' in SOURCE
    assert SOURCE.count('if: always()\n') == 2
    assert SOURCE.index('id: qualify') < SOURCE.index('name: Record outcome') < SOURCE.index('name: Retain exact candidate')


@pytest.mark.parametrize('mode',['commit','kill-successor-before-ack'])
@pytest.mark.parametrize('status',['success','failure'])
def test_actual_always_writer_retains_exact_case_and_harness_source(tmp_path,monkeypatch,mode,status):
    block=SOURCE.split("          /usr/bin/python3 - <<'PY'\n",1)[1].split('\n          PY',1)[0]
    code=textwrap.dedent(block)
    env={'RUNNER_TEMP':str(tmp_path),'OUTCOME_RUN_SHA':'a'*40,'OUTCOME_RUN_ID':'111',
         'OUTCOME_RUN_ATTEMPT':'2','OUTCOME_MODE':mode,'OUTCOME_JOB_STATUS':status,
         'OUTCOME_CHECKOUT':'failure' if status=='failure' else 'success',
         'OUTCOME_SOURCE_PREFLIGHT':'skipped' if status=='failure' else 'success',
         'OUTCOME_QUALIFY':'skipped' if status=='failure' else 'success'}
    monkeypatch.setattr(os,'environ',env)
    exec(compile(code,'workflow-outcome','exec'),{})
    result=json.loads((tmp_path/'app-update/workflow-outcome.json').read_text())
    assert result['mode']==mode and result['source_sha']=='a'*40
    assert result['run_id']=='111' and result['run_attempt']=='2'
    assert result['job_status_before_upload']==status
    assert result['steps']['qualify']==env['OUTCOME_QUALIFY']
    assert result['steps']['source_preflight']==env['OUTCOME_SOURCE_PREFLIGHT']
    assert set(result)=={'schema_version','source_sha','run_id','run_attempt','mode','job_status_before_upload','steps'}


@pytest.mark.parametrize('conclusion',['success','failure','cancelled','skipped',''])
def test_aggregate_requires_entire_matrix_success_even_after_failure(conclusion):
    aggregate=SOURCE.split('  packaged-update-qualification:\n',1)[1]
    assert "if: always() && github.ref == 'refs/heads/main'" in aggregate
    assert 'needs: packaged-commit' in aggregate
    assert 'CASES_RESULT: ${{ needs.packaged-commit.result }}' in aggregate
    command=aggregate.split('        run: ',1)[1].strip()
    assert command=='test "$CASES_RESULT" = success'
    result=subprocess.run(['/bin/sh','-c',command],env={'CASES_RESULT':conclusion},timeout=2,capture_output=True)
    assert (result.returncode==0)==(conclusion=='success')
