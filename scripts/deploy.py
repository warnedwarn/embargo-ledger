import json,re
from pathlib import Path
from genlayer_py import create_client,create_account
from genlayer_py.chains import studionet

ROOT=Path(__file__).parents[1]
ENV=(ROOT.parents[3]/'accounts.env').read_text(encoding='utf-8')
key=re.search(r'^ACCOUNT_2_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)',ENV,re.M).group(1).strip()
account=create_account(account_private_key=key)
client=create_client(chain=studionet,account=account)
tx=client.deploy_contract(code=(ROOT/'contracts'/'contract.py').read_text(encoding='utf-8'),args=[])
print('deployment_tx='+str(tx),flush=True)
receipt=client.wait_for_transaction_receipt(transaction_hash=tx,status='FINALIZED',retries=180,interval=5000,full_transaction=True)
address=receipt.get('data',{}).get('contract_address') or receipt.get('to_address') or receipt.get('recipient')
leader=((receipt.get('consensus_data',{}).get('leader_receipt') or [{}])[0]).get('execution_result')
assert 'MAJORITY_AGREE' in str(receipt.get('result_name','')).upper()
assert str(leader).upper()=='SUCCESS'
print(json.dumps({'contractAddress':address,'deploymentTransaction':str(tx),'wallet':account.address,'leaderExecution':leader},default=str),flush=True)
