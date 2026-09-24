import hashlib
from conftest import CONTRACT
DOCUMENT=b'Public incident report. Private witness: REDACT. Finding: valve failure.'
COMMITMENT=hashlib.sha256(DOCUMENT).hexdigest()
def policy_mocks(vm):
 vm.mock_web(r'policy\.example',{'status':200,'body':'0 Redact private witness identity.\n1 Preserve the technical finding.'});vm.mock_llm(r'.*EmbargoLedger redaction policy inventory.*','{"rule_count":2}')
def setup(vm,deploy,alice,bob,charlie):
 vm.warp('2035-01-01T00:00:00+00:00');vm.sender=alice;policy_mocks(vm);c=deploy(CONTRACT);c.seal('arc-9','0x'+bob.hex(),'0x'+charlie.hex(),COMMITMENT,'https://policy.example/redaction',300,600,600);return c
def reveal(vm,c,bob):
 vm.warp('2035-01-01T00:06:00+00:00');vm.sender=bob;vm.mock_web(r'full\.example',{'status':200,'body':DOCUMENT});c.reveal('arc-9','https://full.example/document')
def review_mocks(vm):
 policy_mocks(vm);vm.mock_web(r'full\.example',{'status':200,'body':DOCUMENT});vm.mock_web(r'public\.example',{'status':200,'body':'Public incident report. Finding: valve failure.'});vm.mock_llm(r'.*EmbargoLedger redaction audit.*','{"compliant":true,"violation_indexes":[],"note":"Witness identity removed and finding preserved."}')
def test_committed_reveal_review_and_release(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);reveal(direct_vm,c,direct_bob);direct_vm.sender=direct_charlie;review_mocks(direct_vm);c.review_release('arc-9','https://public.example/release');assert c.get_accession('arc-9')['state']=='REVIEWED';direct_vm.warp('2035-01-01T00:17:00+00:00');direct_vm.sender=direct_alice;c.finalize_release('arc-9');assert c.get_accession('arc-9')['state']=='RELEASED'
def test_wrong_bytes_cannot_reveal(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);direct_vm.warp('2035-01-01T00:06:00+00:00');direct_vm.sender=direct_bob;direct_vm.mock_web(r'full\.example',{'status':200,'body':'changed'})
 with direct_vm.expect_revert('match commitment'):c.reveal('arc-9','https://full.example/document')
def test_validator_rejects_hidden_policy_violation(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);reveal(direct_vm,c,direct_bob);direct_vm.sender=direct_charlie;review_mocks(direct_vm);c.review_release('arc-9','https://public.example/release');record=c.get_accession('arc-9');result={'compliant':True,'violation_indexes':[],'note':'Witness identity removed and finding preserved.','release_digest':record['release_digest']};assert direct_vm.run_validator(leader_result=result) is True;forged=dict(result);forged['violation_indexes']=[0];assert direct_vm.run_validator(leader_result=forged) is False
def test_public_material_flag_blocks_release(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);reveal(direct_vm,c,direct_bob);direct_vm.sender=direct_charlie;review_mocks(direct_vm);c.review_release('arc-9','https://public.example/release');direct_vm.clear_mocks();direct_vm.sender=direct_alice;policy_mocks(direct_vm);direct_vm.mock_web(r'public\.example',{'status':200,'body':'Public incident report. Finding: valve failure.'});direct_vm.mock_web(r'flag\.example',{'status':200,'body':'The release contains the private witness name.'});direct_vm.mock_llm(r'.*EmbargoLedger public flag review.*','{"material":true,"reason":"Private identity remains visible."}');c.flag_release('arc-9','https://flag.example/proof');assert c.get_accession('arc-9')['state']=='FLAGGED'
def test_oversized_policy_is_rejected_not_truncated(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 direct_vm.warp('2035-01-01T00:00:00+00:00');direct_vm.sender=direct_alice;c=direct_deploy(CONTRACT);direct_vm.mock_web(r'policy\.example',{'status':200,'body':'x'*14001})
 with direct_vm.expect_revert('14000-byte audit limit'):c.seal('arc-big','0x'+direct_bob.hex(),'0x'+direct_charlie.hex(),COMMITMENT,'https://policy.example/redaction',300,600,600)
def test_flag_rejects_mutated_frozen_release(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);reveal(direct_vm,c,direct_bob);direct_vm.sender=direct_charlie;review_mocks(direct_vm);c.review_release('arc-9','https://public.example/release');direct_vm.clear_mocks();direct_vm.sender=direct_alice;policy_mocks(direct_vm);direct_vm.mock_web(r'public\.example',{'status':200,'body':'MUTATED after review'});direct_vm.mock_web(r'flag\.example',{'status':200,'body':'Material breach evidence'})
 with direct_vm.expect_revert('reviewed release changed'):c.flag_release('arc-9','https://flag.example/proof')
def test_flag_rejects_mutated_frozen_policy(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);reveal(direct_vm,c,direct_bob);direct_vm.sender=direct_charlie;review_mocks(direct_vm);c.review_release('arc-9','https://public.example/release');direct_vm.clear_mocks();direct_vm.sender=direct_alice;direct_vm.mock_web(r'policy\.example',{'status':200,'body':'changed policy'});direct_vm.mock_web(r'public\.example',{'status':200,'body':'Public incident report. Finding: valve failure.'});direct_vm.mock_web(r'flag\.example',{'status':200,'body':'Material breach evidence'})
 with direct_vm.expect_revert('frozen policy'):c.flag_release('arc-9','https://flag.example/proof')
def test_missed_reveal_is_permissionless(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
 c=setup(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie);direct_vm.warp('2035-01-01T00:16:00+00:00');direct_vm.sender=direct_charlie;c.mark_missed_reveal('arc-9');assert c.get_accession('arc-9')['state']=='MISSED_REVEAL'
