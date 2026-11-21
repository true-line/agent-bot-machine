"""Create a private Go overlay for the disposable hosted transaction only."""
import hashlib, json
from pathlib import Path
import sys

root=Path(__file__).resolve().parent
policy=json.loads((root/'fixture-policy.json').read_text())
if len(sys.argv)!=4: raise SystemExit('expected Machine checkout, new private output and compiled fixture')
source=Path(sys.argv[1]).resolve()
output=Path(sys.argv[2]).resolve()
if output.exists(): raise SystemExit('use a fresh output directory')
if hashlib.sha256(Path(sys.argv[3]).read_bytes()).hexdigest()!=policy['sha256']: raise SystemExit('unexpected fixture binary')
grant=source/'internal/members/harness_grant_darwin.go'
original=grant.read_text()
needle='func qualifiedHarnessAdapter(a HarnessAdapter) error {\n'
if original.count(needle)!=1: raise SystemExit('unrecognized source predicate')
# Only this inert fixture, in two fixed mappings, under the selected managed
# UIDs and no arguments. All remaining cases use the unchanged production
# predicate. Actual ownership, mode, digest, account and pair checks still run.
cases=' || '.join('(a.ID=='+json.dumps(k)+' && a.Account=='+json.dumps(v)+')' for k,v in policy['mappings'].items())
guard='    if ('+cases+') && a.UID>=300 && a.UID<=399 && a.Executable=='+json.dumps(policy['executable'])+' && a.SHA256=='+json.dumps(policy['sha256'])+' && a.Args!=nil && len(a.Args)==0 { return nil }\n'
output.mkdir(mode=0o700)
new=output/'grant.go';new.write_text(original.replace(needle,needle+guard))
test=output/'fixture_qualification_test.go'
test.write_text('''package members
import "testing"
func TestHostedFixtureScope(t *testing.T) {
 for _,tc:=range []struct{id,account string}{\n'''+''.join('{'+json.dumps(k)+','+json.dumps(v)+'},\n' for k,v in policy['mappings'].items())+'''}{
 a:=HarnessAdapter{ID:tc.id,Account:tc.account,UID:321,Executable:'''+json.dumps(policy['executable'])+',SHA256:'+json.dumps(policy['sha256'])+''',Args:[]string{}}
 if e:=qualifiedHarnessAdapter(a);e!=nil{t.Fatal(e)}
 for i:=0;i<6;i++{ b:=a;switch i{case 0:b.ID="other";case 1:b.Account="_other";case 2:b.UID=0;case 3:b.Executable="/bin/sh";case 4:b.SHA256="";case 5:b.Args=[]string{"new"}};if qualifiedHarnessAdapter(b)==nil{t.Fatal("unexpected fixture permission",i)}}
 }
}
''')
(output/'overlay.json').write_text(json.dumps({'Replace':{str(grant):str(new),str(source/'internal/members/fixture_qualification_darwin_test.go'):str(test)}}))
