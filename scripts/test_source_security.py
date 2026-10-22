"""실제 javac AST의 양성·음성·문자열/주석·분기 입력 추적을 확인한다. 서버/모델 실행 없음."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.workspace import ProductConfig,REPO
from localcode_review_mcp.source_security import scan_source_security


@unittest.skipUnless(os.environ.get('JAVA_HOME') and (REPO/'build/product/classes/dev/localcodereview/SecurityRules.class').exists(),'JDK and product security bridge required')
class SourceSecurityTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.project=self.base/'project';self.project.mkdir()
        self.config=ProductConfig(self.base/'config.json',{'sample':{'root':str(self.project)}},Path(os.environ['JAVA_HOME']),self.base/'results',{})
    def scan(self,body):
        (self.project/'Api.java').write_text('''import org.springframework.web.bind.annotation.*;
import jakarta.persistence.EntityManager;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.HtmlUtils;
@RestController class Api { EntityManager db; RestTemplate web;
'''+body+'\n}',encoding='utf-8')
        return scan_source_security(self.config,'sample')
    def test_three_actual_sinks_and_safe_counterparts(self):
        report=self.scan('''
@GetMapping("/sql") Object sql(@RequestParam String q){String s="select x where x='"+q+"'";return db.createQuery(s);}
@GetMapping("/sql-safe") Object sqlSafe(@RequestParam String q){return db.createQuery("select x where x=:q").setParameter("q",q);}
@GetMapping(value="/html",produces="text/html") String html(@RequestParam String q){return q;}
@GetMapping(value="/html-safe",produces="text/html") String htmlSafe(@RequestParam String q){return HtmlUtils.htmlEscape(q);}
@GetMapping("/url") String url(@RequestParam String u){return web.getForObject(u,String.class);}
@GetMapping("/url-safe") String urlSafe(@RequestParam String ignored){return web.getForObject("http://fixed.invalid",String.class);}
''')
        self.assertEqual({'LCR-SQL-001','LCR-XSS-001','LCR-SSRF-001'},{f['rule_id'] for f in report['findings']})
        self.assertEqual(3,len(report['findings']))
        self.assertFalse(report['errors'])
        self.assertTrue(all(f['security_cause_confirmed'] is False for f in report['findings']))
    def test_comment_and_string_lookalikes_do_not_create_findings(self):
        r=self.scan('''@GetMapping("/text") String x(@RequestParam String q){
// web.getForObject(q,String.class)
String message="db.createQuery(q)";return message;}
''')
        self.assertEqual([],r['findings'])
    def test_branch_union_preserves_taint_and_definite_overwrite_clears_it(self):
        r=self.scan('''@GetMapping("/branch") Object x(@RequestParam String q, boolean condition){
String sql="select 1";if(condition){sql=q;}else{sql="select 2";}return db.createQuery(sql);}
@GetMapping("/constant") Object y(@RequestParam String q){String sql=q;sql="select 1";return db.createQuery(sql);}
''')
        self.assertEqual(1,len(r['findings']));self.assertEqual('x',r['findings'][0]['method'])
    def test_unresolved_transform_is_conservatively_kept(self):
        r=self.scan('''@GetMapping("/transform") Object x(@RequestParam String q){return db.createQuery(customClean(q));}
String customClean(String q){return q;}''')
        self.assertEqual(1,len(r['findings']))
    def test_html_encoding_does_not_sanitize_sql_or_url(self):
        r=self.scan('''@GetMapping("/sql") Object x(@RequestParam String q){String encoded=HtmlUtils.htmlEscape(q);return this.db.createQuery(encoded);}
@GetMapping("/url") String y(@RequestParam String q){return this.web.getForObject(HtmlUtils.htmlEscape(q),String.class);}
@GetMapping(value="/html",produces="text/html") String z(@RequestParam String q){String encoded=HtmlUtils.htmlEscape(q);return encoded;}
''')
        self.assertEqual({'LCR-SQL-001','LCR-SSRF-001'},{f['rule_id'] for f in r['findings']})
        self.assertEqual(2,len(r['findings']))


if __name__=='__main__':unittest.main()
