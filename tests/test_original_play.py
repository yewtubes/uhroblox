"""Execute exact captured launch branches; never recreate their UI or handlers."""
import json
import subprocess
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def node(code):
    return json.loads(subprocess.check_output(['node', '-e', code], text=True))


class OriginalPlayTests(unittest.TestCase):
    def original(self, name):
        return (ROOT/'evidence'/('original-play-'+name+'.js')).read_text()

    def guest_run(self, authenticated=False, action=None):
        setup = '''
const state={dialogs:0,launches:0,resolved:false,events:[]};
const window={location:{origin:'http://localhost:3000',pathname:'/games/42/local-experience',search:'?source=local',href:''}};
let dialog;
class Deferred {
  resolve(value){this.resolved=true;this.value=value;state.resolved=true;return this;}
  then(fn){if(this.resolved)fn(this.value);return this;}
}
const jquery={Deferred};
const V=()=>jquery;
const F={get:key=>key};
const W={CurrentUser:{isAuthenticated:AUTHENTICATED},
  Dialog:{green:'original-style-token',open:options=>{state.dialogs++;dialog=options;}},
  FormEvents:{SendInteractionClick:(...args)=>state.events.push(args)},
  Endpoints:{getAbsoluteUrl:path=>path}};
'''.replace('AUTHENTICATED', json.dumps(authenticated))
        run = '''
const data={placeId:42,joinAttemptId:'local-attempt'};
sz.restrictGuests(data).then(value=>{state.launches++;state.launchData=value;});
'''
        if action:
            run += 'dialog.'+action+'();\n'
        run += '''
state.destination=window.location.href;
state.translationKeys=dialog?[dialog.titleText,dialog.bodyContent,dialog.acceptText,dialog.declineText]:[];
console.log(JSON.stringify(state));
'''
        return node(setup+self.original('guestRestriction')+run)

    def test_guest_play_opens_original_dialog_without_joining(self):
        result = self.guest_run()
        self.assertEqual(result['dialogs'], 1)
        self.assertEqual(result['launches'], 0)
        self.assertFalse(result['resolved'])
        self.assertEqual(result['translationKeys'], [
            'Heading.Dialog.SignUpOrLogin', 'Description.Dialog.ConnectionsSignUpOrLogin',
            'Action.Dialog.SignUp', 'Action.Dialog.Login'])

    def test_guest_login_preserves_local_return_to_game(self):
        result = self.guest_run(action='onDecline')
        dest = urlsplit(result['destination'])
        self.assertEqual(dest.path, '/login')
        self.assertEqual(parse_qs(dest.query)['returnurl'], ['http://localhost:3000/games/42/local-experience?source=local'])
        self.assertEqual(result['launches'], 0)

    def test_guest_signup_preserves_local_return_to_game(self):
        result = self.guest_run(action='onAccept')
        dest = urlsplit(result['destination'])
        self.assertEqual(dest.path, '/CreateAccount')
        self.assertEqual(parse_qs(dest.query)['returnurl'], ['http://localhost:3000/games/42/local-experience?source=local'])
        self.assertEqual(result['launches'], 0)

    def test_authenticated_branch_resolves_without_guest_dialog(self):
        result = self.guest_run(authenticated=True)
        self.assertEqual(result['dialogs'], 0)
        self.assertEqual(result['launches'], 1)
        self.assertTrue(result['resolved'])
        self.assertEqual(result['launchData']['placeId'], 42)

    def test_modern_missing_user_guard_redirects_before_any_launch(self):
        setup = '''
let launched=false;
const window={location:{href:'http://localhost:3000/games/42/local-experience?source=local'}};
const rB=()=>undefined;
'''
        run = '''
const launcher={joinMultiplayerGame:()=>{launched=true;}};
rG(launcher,{placeId:42},{eventName:'playGameClicked',ctx:'click',properties:{}});
console.log(JSON.stringify({launched,destination:window.location.href}));
'''
        result = node(setup+self.original('loginRedirect')+self.original('authenticatedLaunchGuard')+run)
        self.assertFalse(result['launched'])
        dest = urlsplit(result['destination'])
        self.assertEqual(dest.path, '/login')
        self.assertEqual(parse_qs(dest.query)['returnUrl'], ['http://localhost:3000/games/42/local-experience?source=local'])

    def test_original_play_fragments_match_captured_bundle_exactly(self):
        meta=json.loads((ROOT/'evidence/original-play-branches.json').read_text())
        text=(ROOT/'capture/objects'/meta['source_sha256']).read_text()
        for part in meta['parts'].values():
            original=text[part['start_offset']:part['end_offset']]
            expected=original if original.startswith('var ') else 'var '+original
            self.assertEqual((ROOT/'evidence'/part['file']).read_text(),expected+';\n')
        self.assertIn('i===eh.GuestProhibited&&(X?nH.navigateToLoginWithRedirect():r6(r,s))',text)


if __name__=='__main__':
    unittest.main()
