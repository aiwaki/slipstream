"""Execute the worker's actual DOM observation expression with a virtual clock."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'app-tauri/src-tauri/src/browser_probe.rs'


@unittest.skipUnless(shutil.which('node'), 'Node is required for the DOM expression contract')
class DynamicImageObservationTests(unittest.TestCase):
    def observe(self, budget, delay, host='images.example.net'):
        source = SOURCE.read_text()
        start = source.index('let expression = format!(r#"new Promise', source.index('fn discover_dynamic_image'))
        start = source.index('r#"', start) + 3
        expression = source[start:source.index('"#);', start)]
        expression = expression.replace('{host_json}', json.dumps(['images.example.net']))
        expression = expression.replace('{observation_ms}', str(budget)).replace('{{', '{').replace('}}', '}')
        script = r'''
const vm = require('node:vm');
(async () => {
 let now=0, timers=[]; const document={images:[]};
 const context={document, URL, Date:{now:()=>now}, setTimeout:(f,t)=>timers.push({at:now+t,f})};
 timers.push({at:DELAY,f:()=>document.images.push({src:'https://HOST/late.png'})});
 let done=false,value;
 vm.runInNewContext(EXPRESSION,context).then(v=>{done=true;value=v});
 for(let n=0;n<1000 && !done;n++) {
  await Promise.resolve(); if(done)break;
  timers.sort((a,b)=>a.at-b.at); const timer=timers.shift();
  if(!timer)throw Error('observer did not settle'); now=timer.at;timer.f();
 }
 if(!done)throw Error('observer exceeded bounded iterations');
 console.log(JSON.stringify({found:!!value,elapsed:now}));
})();
'''.replace('DELAY', str(delay)).replace('HOST', host).replace('EXPRESSION', json.dumps(expression))
        result = subprocess.run(['node', '-e', script], text=True, capture_output=True, check=True, timeout=5)
        return json.loads(result.stdout)

    def test_hydration_after_three_seconds_is_observed(self):
        self.assertEqual(self.observe(6000, 4000), {'found': True, 'elapsed': 4000})

    def test_original_budget_still_bounds_missing_resource(self):
        self.assertEqual(self.observe(2000, 4000), {'found': False, 'elapsed': 2000})

    def test_unlisted_host_never_becomes_discovery_hint(self):
        self.assertEqual(self.observe(6000, 4000, 'other.example.net'), {'found': False, 'elapsed': 6000})


if __name__ == '__main__':
    unittest.main()
