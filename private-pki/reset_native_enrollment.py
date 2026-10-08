#!/usr/bin/env python3
"""Root operator reset for an offline AP. Dry-run unless explicitly applied.
Retains signing/revocation/audit history. Does not revoke gateway TLS sessions.
Never loads CA keys, accepts a batch key or modifies controller/AP configuration.
"""
import argparse,hashlib,json,os,re,sqlite3,stat,time
from pathlib import Path

REQUIRED={'issued','inventory','identity_lifecycle','lifecycle_history','operator_audit',
          'campaign_members','enrollment_campaigns','grants','audit','onboarding_jobs'}
def checked_file(path):
    p=Path(path);s=p.lstat()
    if not p.is_absolute() or p.resolve()!=p or not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:raise ValueError('Unsafe state file')
    checked_dir(p.parent);return p
def checked_dir(p):
    s=p.lstat()
    if not p.is_absolute() or p.resolve()!=p or not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('Unsafe private directory')
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def public_row(row):
    return {k:(bytes(v).hex() if isinstance(v,(bytes,bytearray)) else v) for k,v in dict(row).items()}
def tables(db):return {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
def snapshot(db,serial,leaf):
    if not re.fullmatch('[0-9a-f]{12}',serial) or not re.fullmatch('[0-9a-f]{64}',leaf):raise ValueError('Exact canonical serial and full certificate reference required')
    ts=tables(db)
    if not REQUIRED<=ts:raise ValueError('Unknown or incomplete enrollment schema')
    leaves=[public_row(r) for r in db.execute('SELECT fingerprint,device,issuer,expires,revoked FROM issued WHERE device=? ORDER BY fingerprint',(serial,))]
    if not any(r['fingerprint']==leaf for r in leaves):raise ValueError('Expected certificate does not belong to this AP')
    life=db.execute('SELECT * FROM identity_lifecycle WHERE serial=?',(serial,)).fetchone();inv=db.execute('SELECT * FROM inventory WHERE serial=?',(serial,)).fetchone()
    if not life or not inv:raise ValueError('Known lifecycle and inventory required')
    owner=json.loads(life['ownership'])
    if not isinstance(owner,dict) or owner.get('serial')!=serial or not owner.get('inventoryId'):raise ValueError('Unknown ownership state')
    if db.execute('SELECT 1 FROM campaign_members m LEFT JOIN enrollment_campaigns c ON c.id=m.campaign WHERE m.serial=? AND c.id IS NULL',(serial,)).fetchone():
        raise ValueError('Orphan enrollment membership; review before reset')
    members=[public_row(r) for r in db.execute('''SELECT m.campaign,m.serial,m.ownership,m.csr_digest,m.response,m.qualification,c.digest,c.active,c.operation FROM campaign_members m JOIN enrollment_campaigns c ON c.id=m.campaign WHERE m.serial=? ORDER BY m.campaign''',(serial,))]
    if any(json.loads(m['ownership'])!=owner for m in members):raise ValueError('Enrollment ownership differs from lifecycle')
    jobs=[public_row(r) for r in db.execute('SELECT id,state FROM onboarding_jobs WHERE serial=? ORDER BY id',(serial,))]
    if any(j['state'] not in ['complete','failed','cancelled'] for j in jobs):raise ValueError('Finish or cancel active/unknown onboarding jobs before reset')
    grant_rows=[public_row(r) for r in db.execute('SELECT * FROM grants WHERE serial=? ORDER BY digest',(serial,))]
    cached={}
    if 'migration_grants' in ts:cached['migration_grants']=[public_row(r) for r in db.execute('SELECT * FROM migration_grants WHERE digest IN (SELECT digest FROM grants WHERE serial=?) ORDER BY digest',(serial,))]
    if 'onboarding_grants' in ts:cached['onboarding_grants']=[public_row(r) for r in db.execute('SELECT * FROM onboarding_grants WHERE job IN (SELECT id FROM onboarding_jobs WHERE serial=?) ORDER BY digest',(serial,))]
    if 'native_commands' in ts:cached['native_commands']=[public_row(r) for r in db.execute('SELECT * FROM native_commands WHERE job IN (SELECT id FROM onboarding_jobs WHERE serial=?) ORDER BY job',(serial,))]
    if 'activation_challenges' in ts:cached['activation_challenges']=[public_row(r) for r in db.execute('SELECT * FROM activation_challenges WHERE device=? ORDER BY nonce',(serial,))]
    if 'renewal_replies' in ts:cached['renewal_replies']=[public_row(r) for r in db.execute('SELECT * FROM renewal_replies WHERE substr(request,1,64) IN (SELECT fingerprint FROM issued WHERE device=?) ORDER BY request',(serial,))]
    result={'serial':serial,'expected_leaf':leaf,'leaves':leaves,'lifecycle':public_row(life),'inventory':public_row(inv),'members':members,'jobs':jobs,'grants':grant_rows,'cached':cached}
    result['binding']=hashlib.sha256(canonical(result).encode()).hexdigest()
    result['reset_done']=all(r['revoked']==1 for r in leaves) and not members and not grant_rows and not inv['enabled'] and life['retired']==1 and not life['approved'] and not life['enabled']
    return result

def run(state,serial,leaf,expected_binding=None,apply=False,backup_dir=None,offline=False):
    path=checked_file(state)
    ro=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True);ro.row_factory=sqlite3.Row
    initial=snapshot(ro,serial,leaf)
    if initial['reset_done']:
        event=ro.execute("SELECT 1 FROM operator_audit WHERE action='native-enrollment-reset' AND target=?",(serial+':'+leaf+':'+str(expected_binding),)).fetchone()
        if not event:raise ValueError('Completed reset requires its original binding receipt')
        ro.close();return {'state':'already-reset','serial':serial,'expected_leaf':leaf,'binding':expected_binding}
    if not any(r['fingerprint']==leaf and not r['revoked'] for r in initial['leaves']):raise ValueError('Expected current certificate is already revoked; review state')
    if not apply:
        ro.close();return {'state':'dry-run','serial':serial,'expected_leaf':leaf,'binding':initial['binding'],'leaf_count':len(initial['leaves']),'member_count':len(initial['members']),'job_count':len(initial['jobs']),'gateway_revocation_enforced':False,'requires':'AP on OEM/offline with old private identity cleared; exact binding and private backup directory'}
    if not offline or not backup_dir or expected_binding!=initial['binding']:raise ValueError('Apply requires offline identity-cleared confirmation, private backup and exact dry-run binding')
    dest=Path(backup_dir);checked_dir(dest.parent)
    if dest.exists() or dest.is_symlink():raise ValueError('Backup destination must be new')
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row;db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
    try:
        if snapshot(db,serial,leaf)['binding']!=expected_binding:raise ValueError('Target state changed; rerun dry-run')
        dest.mkdir(mode=0o700)
        backup=dest/'issuer.sqlite';fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        copy=sqlite3.connect(backup);ro.backup(copy)
        if copy.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('Backup integrity check failed')
        copy.close()
        with backup.open('rb') as f:backup_hash=hashlib.sha256(f.read()).hexdigest()
        manifest={'target':initial,'backup_sha256':backup_hash,'scope':'private full SQLite recovery copy; do not restore over unrelated later AP changes','gateway_revocation_enforced':False}
        record=dest/'reset-before.json';record.write_text(json.dumps(manifest,indent=2)+'\n');record.chmod(0o600);os.sync()
        # Recheck after backup while holding the target mutation transaction.
        if snapshot(db,serial,leaf)['binding']!=expected_binding:raise ValueError('Target state changed after backup')
        now=int(time.time());fps=[r['fingerprint'] for r in initial['leaves']]
        for fp in fps:
            db.execute('UPDATE issued SET revoked=1 WHERE fingerprint=? AND device=?',(fp,serial))
            db.execute('INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)',(now,'certificate-revoked:'+fp,serial))
        life=initial['lifecycle'];version=life['version']+1
        db.execute('UPDATE identity_lifecycle SET version=?,approved=0,enabled=0,retired=1,actor=?,stamp=? WHERE serial=?',(version,'root-local-reset',now,serial))
        db.execute('INSERT INTO lifecycle_history(serial,version,approved,enabled,retired,ownership,actor,stamp) VALUES (?,?,0,0,1,?,?,?)',(serial,version,life['ownership'],'root-local-reset',now))
        db.execute('UPDATE inventory SET enabled=0 WHERE serial=?',(serial,))
        ts=tables(db)
        if 'migration_grants' in ts:db.execute('DELETE FROM migration_grants WHERE digest IN (SELECT digest FROM grants WHERE serial=?)',(serial,))
        db.execute('DELETE FROM grants WHERE serial=?',(serial,))
        if 'onboarding_grants' in ts:db.execute('DELETE FROM onboarding_grants WHERE job IN (SELECT id FROM onboarding_jobs WHERE serial=?)',(serial,))
        if 'native_commands' in ts:db.execute("UPDATE native_commands SET state='cancelled' WHERE job IN (SELECT id FROM onboarding_jobs WHERE serial=?)",(serial,))
        if 'activation_challenges' in ts:db.execute('DELETE FROM activation_challenges WHERE device=?',(serial,))
        if 'renewal_replies' in ts:
            for fp in fps:db.execute('DELETE FROM renewal_replies WHERE substr(request,1,64)=?',(fp,))
        db.execute('DELETE FROM campaign_members WHERE serial=?',(serial,))
        db.execute('INSERT INTO operator_audit(stamp,actor,action,target) VALUES (?,?,?,?)',(now,'root-local-reset','native-enrollment-reset',serial+':'+leaf+':'+expected_binding))
        db.commit()
    except Exception:
        db.rollback();raise
    finally:db.close();ro.close()
    sync_status='complete'
    try:os.sync()
    except OSError:sync_status='post-commit sync failed; reset committed, verify using the original binding receipt'
    return {'state':'reset','post_commit_sync':sync_status,'serial':serial,'expected_leaf':leaf,'binding':expected_binding,'backup':str(dest),'backup_sha256':backup_hash,'gateway_revocation_enforced':False,'next':'Root creates a new approved enrollment batch after authoritative inventory/ownership is ready; AP generates a new key/CSR'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state',type=Path,default=Path('/opt/openwifi/ap-pki-private/portal-state/issuer.sqlite'));p.add_argument('--serial',required=True);p.add_argument('--expected-leaf',required=True);p.add_argument('--expected-binding');p.add_argument('--backup-dir',type=Path);p.add_argument('--apply',action='store_true');p.add_argument('--offline-identity-cleared',action='store_true');a=p.parse_args()
    if os.geteuid()!=0:p.error('Run as Root; no tokens or private CA keys are required')
    os.umask(0o077)
    try:print(json.dumps(run(a.state,a.serial,a.expected_leaf,a.expected_binding,a.apply,a.backup_dir,a.offline_identity_cleared)))
    except (ValueError,OSError,sqlite3.Error) as e:p.exit(1,'Reset refused: '+str(e)+'\n')
if __name__=='__main__':main()
