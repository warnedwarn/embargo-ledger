import hashlib,json,re,time
from pathlib import Path
from genlayer_py import create_client,create_account
from genlayer_py.chains import studionet

ROOT=Path(__file__).parents[1]
ENV=(ROOT.parents[3]/'accounts.env').read_text(encoding='utf-8')
DEP=json.loads((ROOT/'deployment.json').read_text(encoding='utf-8'))
def account(slot):
 key=re.search(rf'^ACCOUNT_{slot}_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)',ENV,re.M).group(1).strip()
 return create_account(account_private_key=key)
owner,custodian,reviewer=account(2),account(3),account(4)
client=create_client(chain=studionet,account=owner)
record='REMEDIATION-'+str(int(time.time()))
commit=DEP['sourceCommit']
policy=f'https://raw.githubusercontent.com/warnedwarn/embargo-ledger/{commit}/evidence/policy.txt'
document=(ROOT/'evidence'/'full-document.txt').read_bytes()
commitment=hashlib.sha256(document).hexdigest()
tx=client.write_contract(address=DEP['contractAddress'],function_name='seal',args=[record,custodian.address,reviewer.address,commitment,policy,300,600,600],value=0)
print('seal_tx='+str(tx),flush=True)
receipt=client.wait_for_transaction_receipt(transaction_hash=tx,status='FINALIZED',retries=180,interval=5000,full_transaction=True)
leader=((receipt.get('consensus_data',{}).get('leader_receipt') or [{}])[0]).get('execution_result')
assert 'MAJORITY_AGREE' in str(receipt.get('result_name','')).upper()
assert str(leader).upper()=='SUCCESS'
state=client.read_contract(address=DEP['contractAddress'],function_name='get_accession',args=[record])
assert state['state']=='SEALED'
print(json.dumps({'recordId':record,'transaction':str(tx),'state':state['state'],'policyDigest':state['policy_digest'],'leaderExecution':leader}),flush=True)
