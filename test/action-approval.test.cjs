'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {handleHook}=require('../src/hook-policy.cjs');

// Approval tests must not depend on package managers installed on the host.
// The entries are fingerprinted but never executed by this suite.
const managerFixture = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-approval-managers-'));
const previousPath = process.env.PATH;
for (const [manager, entry] of [['pnpm', 'pnpm.cjs'], ['npm', 'npm-cli.js']]) {
  const bin = path.join(managerFixture, 'node_modules', manager, 'bin');
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, entry), '// test-only manager fixture\n');
}
process.env.PATH = [managerFixture, previousPath || ''].join(path.delimiter);
test.after(() => {
  process.env.PATH = previousPath;
  fs.rmSync(managerFixture, { recursive: true, force: true });
});
test('explicit card authorizes only the exact denied dependency action once',t=>{
 const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'sts-action-'));t.after(()=>fs.rmSync(dataDir,{recursive:true,force:true}));const options={dataDir};const base={session_id:'approval-test',turn_id:'t',cwd:process.cwd()};
 const prompt=prompt=>handleHook({...base,hook_event_name:'UserPromptSubmit',prompt},options);
 const before=(id,name,input)=>handleHook({...base,hook_event_name:'PreToolUse',tool_name:name,tool_use_id:id,tool_input:input},options);
 prompt('$stop-that-shit change deps=ask -- work');const input={command:'pnpm install --offline --frozen-lockfile --ignore-scripts'};
 const denied=before('install-1','Bash',input);const reason=denied.hookSpecificOutput.permissionDecisionReason;assert.match(reason,/DEPENDENCY_NOT_AUTHORIZED/);assert.doesNotMatch(reason,/obtain explicit deps=allow/);assert.match(reason,/session.*deps=ask/i);
 const match=/Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(reason);assert.ok(match,'denial must provide exact question and options');
 const question=match[1].replace('<absolute canonical directory>',fs.realpathSync(process.cwd())),yes=match[2],no=match[3];assert.equal(before('question-1','request_user_input_async',{questions:[{title:question,options:[yes,no]}]}),null);
 const reply=JSON.stringify([{questionItemId:JSON.stringify(['request_user_input_async','question-1',0]),question,answer:yes}]);prompt(`<send_user_message_question_reply>\n${reply}\n</send_user_message_question_reply>`);
 assert.equal(before('install-2','Bash',input).hookSpecificOutput.permissionDecision,'allow');
 const {readRuntime}=require('../src/runtime-audit.cjs');
 const runtime=readRuntime({sessionId:'approval-test'},options);
 const issued=runtime.events.find(event=>event.approval && !event.approval.consumed);
 assert.ok(issued);assert.equal(issued.approval.questionCallId,'question-1');assert.match(issued.approval.eventId,/^evt_/);
 assert.doesNotMatch(JSON.stringify(issued),/pnpm install|Allow this operation once/);
 assert.equal(before('install-3','Bash',input).hookSpecificOutput.permissionDecision,'allow');
});

test('approval rejects forged, changed, replayed and unsafe operations',t=>{
 const dataDir=fs.mkdtempSync(path.join(os.tmpdir(),'sts-approval-'));t.after(()=>fs.rmSync(dataDir,{recursive:true,force:true}));const options={dataDir};const cwd=process.cwd();
 const base={session_id:'s',turn_id:'t',cwd};const prompt=(text,more={})=>handleHook({...base,...more,hook_event_name:'UserPromptSubmit',prompt:text},options);
 const before=(id,name,input,more={})=>handleHook({...base,...more,hook_event_name:'PreToolUse',tool_name:name,tool_use_id:id,tool_input:input},options);
 const input={command:'pnpm install --offline --frozen-lockfile --ignore-scripts'};prompt('$stop-that-shit change deps=ask -- work');
 let r=before('a','Bash',input);let m=/Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(r.hookSpecificOutput.permissionDecisionReason);assert.ok(m);let [_,question,yes,no]=m;question=question.replace('<absolute canonical directory>',fs.realpathSync(cwd));
 const reply=(id,answer=yes)=>`<send_user_message_question_reply>\n${JSON.stringify([{questionItemId:JSON.stringify(['request_user_input_async',id,0]),question,answer}])}\n</send_user_message_question_reply>`;
 before('q','request_user_input_async',{questions:[{title:question,options:[yes,no]}]});
 for(const value of [reply('wrong'),`quoted ${reply('q')}`,`\`\`\`\n${reply('q')}\n\`\`\``,`<heartbeat>${reply('q')}</heartbeat>`]) prompt(value);
 prompt(reply('q'),{session_id:'other'});
 assert.match(before('different','Bash',{command:input.command+' && echo done'}).hookSpecificOutput.permissionDecisionReason,/DEPENDENCY_NOT_AUTHORIZED/);
 prompt(reply('q'));assert.match(before('b','Bash',input,{cwd:cwd+'-other'}).hookSpecificOutput.permissionDecisionReason,/DEPENDENCY_NOT_AUTHORIZED/);
});

test('denial, expiration, mode changes and hash policy remain authoritative', t => {
 const {readState,writeState}=require('../src/state.cjs');const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sts-bound-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const opt={dataDir:dir};const base={session_id:'bounded',turn_id:'t',cwd:process.cwd()};const prompt=text=>handleHook({...base,hook_event_name:'UserPromptSubmit',prompt:text},opt);const before=(id,name,input)=>handleHook({...base,hook_event_name:'PreToolUse',tool_name:name,tool_use_id:id,tool_input:input},opt);const input={command:'pnpm install --offline --frozen-lockfile --ignore-scripts'};
 function prepare(){const d=before('a','Bash',input);const m=/Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(d.hookSpecificOutput.permissionDecisionReason);assert.ok(m);m[1]=m[1].replace('<absolute canonical directory>',fs.realpathSync(base.cwd));before('q','request_user_input_async',{questions:[{title:m[1],options:[m[2],m[3]]}]});return answer=>`<send_user_message_question_reply>\n${JSON.stringify([{questionItemId:JSON.stringify(['request_user_input_async','q',0]),question:m[1],answer}])}\n</send_user_message_question_reply>`;}
 prompt('$stop-that-shit change deps=deny -- work');const denyReason=before('deny','Bash',input).hookSpecificOutput.permissionDecisionReason;assert.doesNotMatch(denyReason,/Approval question:/);assert.match(denyReason,/deps=allow/);
 prompt('$stop-that-shit change deps=ask -- work');let reply=prepare();prompt(reply('Deny this operation'));assert.match(before('b','Bash',input).hookSpecificOutput.permissionDecisionReason,/DEPENDENCY_NOT_AUTHORIZED/);
 reply=prepare();let state=readState('bounded',dir);state.actionApproval.proposalExpires=Date.now()-1;writeState('bounded',state,dir);prompt(reply('Allow this operation once'));assert.match(before('c','Bash',input).hookSpecificOutput.permissionDecisionReason,/DEPENDENCY_NOT_AUTHORIZED/);
 reply=prepare();prompt(reply('Allow this operation once'));prompt('$stop-that-shit review -- inspect');assert.match(before('d','Bash',input).hookSpecificOutput.permissionDecisionReason,/MODE_FORBIDS_MUTATION/);prompt('$stop-that-shit change deps=ask -- work');assert.match(before('e','Bash',input).hookSpecificOutput.permissionDecisionReason,/DEPENDENCY_NOT_AUTHORIZED/);
});

test('hook stdin persists one approval across separate processes',t=>{
 const {spawnSync}=require('node:child_process');const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sts-stdin-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const base={session_id:'stdin',turn_id:'t',cwd:process.cwd()};
 const call=(kind,extra)=>{const r=spawnSync(process.execPath,[path.join(__dirname,'../hooks/stop-that-shit.cjs')],{input:JSON.stringify({...base,hook_event_name:kind,...extra}),env:{...process.env,PLUGIN_DATA:dir,STS_RUNTIME_DATA:dir},encoding:'utf8'});assert.equal(r.status,0,r.stderr);return r.stdout?JSON.parse(r.stdout):null};
 call('UserPromptSubmit',{prompt:'$stop-that-shit change deps=ask -- work'});const input={command:'pnpm install --offline --frozen-lockfile --ignore-scripts'};const pre=(id,tool_name,tool_input)=>call('PreToolUse',{tool_name,tool_use_id:id,tool_input});const d=pre('a','Bash',input);const m=/Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(d.hookSpecificOutput.permissionDecisionReason);assert.ok(m);m[1]=m[1].replace('<absolute canonical directory>',fs.realpathSync(base.cwd));assert.equal(pre('q','request_user_input_async',{questions:[{title:m[1],options:[m[2],m[3]]}]}),null);call('UserPromptSubmit',{prompt:`<send_user_message_question_reply>\n${JSON.stringify([{questionItemId:JSON.stringify(['request_user_input_async','q',0]),question:m[1],answer:m[2]}])}\n</send_user_message_question_reply>`});assert.equal(pre('b','Bash',input).hookSpecificOutput.permissionDecision,'allow');assert.equal(pre('b','Bash',input).hookSpecificOutput.permissionDecision,'allow');
});

test('concurrent retries consume the permit at most once',async t=>{
 const {spawn,spawnSync}=require('node:child_process');const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sts-race-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const base={session_id:'race',turn_id:'t',cwd:process.cwd()},env={...process.env,PLUGIN_DATA:dir,STS_RUNTIME_DATA:dir},entry=path.join(__dirname,'../hooks/stop-that-shit.cjs');
 const run=(kind,extra)=>{const r=spawnSync(process.execPath,[entry],{input:JSON.stringify({...base,hook_event_name:kind,...extra}),env,encoding:'utf8'});assert.equal(r.status,0,r.stderr);return r.stdout?JSON.parse(r.stdout):null};const input={command:'pnpm install --offline --frozen-lockfile --ignore-scripts'};run('UserPromptSubmit',{prompt:'$stop-that-shit change deps=ask -- work'});let d=run('PreToolUse',{tool_name:'Bash',tool_use_id:'original',tool_input:input});let m=/Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(d.hookSpecificOutput.permissionDecisionReason);assert.ok(m);m[1]=m[1].replace('<absolute canonical directory>',fs.realpathSync(base.cwd));run('PreToolUse',{tool_name:'request_user_input_async',tool_use_id:'q',tool_input:{questions:[{title:m[1],options:[m[2],m[3]]}]}});run('UserPromptSubmit',{prompt:`<send_user_message_question_reply>\n${JSON.stringify([{questionItemId:JSON.stringify(['request_user_input_async','q',0]),question:m[1],answer:m[2]}])}\n</send_user_message_question_reply>`});
 const runAsync=id=>new Promise((resolve,reject)=>{const p=spawn(process.execPath,[entry],{env});let out='',err='';p.stdout.on('data',x=>out+=x);p.stderr.on('data',x=>err+=x);p.on('error',reject);p.on('close',code=>code===0?resolve(out?JSON.parse(out):null):reject(Error(err)));p.stdin.end(JSON.stringify({...base,hook_event_name:'PreToolUse',tool_name:'Bash',tool_use_id:id,tool_input:input}));});
 const results=await Promise.all([runAsync('one'),runAsync('two')]);assert.equal(results.filter(x=>x?.hookSpecificOutput?.permissionDecision==='allow').length,2);assert.equal(results[0].hookSpecificOutput.updatedInput.command,results[1].hookSpecificOutput.updatedInput.command);
});

test('direct supported dependency operations bind exact flags and reject shell chains',t=>{
 const {isDirectDependencyCommand}=require('../src/shell-analysis.cjs');
 for(const command of ['npm install package','pnpm add package','yarn install','pip install package','cargo add pkg','dotnet add app.csproj package Example','go get example.org/pkg','composer require vendor/pkg','bundle add pkg']) assert.equal(isDirectDependencyCommand(command),true,command);
 assert.equal(isDirectDependencyCommand("pwsh -NoProfile -Command 'pnpm install --offline'"),true);
 for(const command of ['pnpm install && echo done','npm install > out.txt','npm install $(other)',"pwsh -Command 'npm install; echo done'",'pwsh -EncodedCommand anything','node script.js npm install']) assert.equal(isDirectDependencyCommand(command),false,command);
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sts-flags-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const opt={dataDir:dir};const base={session_id:'flags',turn_id:'t',cwd:process.cwd()};const prompt=prompt=>handleHook({...base,hook_event_name:'UserPromptSubmit',prompt},opt),pre=(id,tool_input)=>handleHook({...base,hook_event_name:'PreToolUse',tool_name:'Bash',tool_use_id:id,tool_input},opt);
 for(const command of ['npm install package','pnpm add package']) {base.session_id = command;prompt('$stop-that-shit change deps=ask -- work');let denied=pre('original',{command});let m=/Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(denied.hookSpecificOutput.permissionDecisionReason);assert.ok(m,command);m[1]=m[1].replace('<absolute canonical directory>',fs.realpathSync(base.cwd));handleHook({...base,hook_event_name:'PreToolUse',tool_name:'request_user_input_async',tool_use_id:'q',tool_input:{questions:[{title:m[1],options:[m[2],m[3]]}]}},opt);prompt(`<send_user_message_question_reply>\n${JSON.stringify([{questionItemId:JSON.stringify(['request_user_input_async','q',0]),question:m[1],answer:m[2]}])}\n</send_user_message_question_reply>`);assert.match(pre('changed',{command:command+' --ignore-scripts'}).hookSpecificOutput.permissionDecisionReason,/DEPENDENCY_NOT_AUTHORIZED/);assert.equal(pre('exact',{command}).hookSpecificOutput.permissionDecision,'allow');}
});

test('other policy gates take precedence and no approval is generated for unsafe inputs',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sts-gates-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const opt={dataDir:dir},base={session_id:'gates',turn_id:'t',cwd:process.cwd()};const prompt=prompt=>handleHook({...base,hook_event_name:'UserPromptSubmit',prompt},opt);const pre=(command,extra={})=>handleHook({...base,...extra,hook_event_name:'PreToolUse',tool_name:'Bash',tool_use_id:'id',tool_input:{command}},opt);
 prompt('$stop-that-shit change deps=ask hash=deny -- work');let output=pre('npm install sha256sum');assert.match(output.hookSpecificOutput.permissionDecisionReason,/HASH_NOT_AUTHORIZED/);assert.doesNotMatch(output.hookSpecificOutput.permissionDecisionReason,/Approval question:/);
 prompt('$stop-that-shit change deps=ask files=src/** -- work');output=pre('npm install package');assert.match(output.hookSpecificOutput.permissionDecisionReason,/WRITE_PATH_UNPROVEN/);assert.doesNotMatch(output.hookSpecificOutput.permissionDecisionReason,/Approval question:/);
});

test('card reply accepts exactly the host UTF-8 truncation, not an arbitrary prefix',()=>{
 const {hostQuestionText}=require('../src/action-approval.cjs');
 const question='字'.repeat(180)+'\nend';
 const truncated=hostQuestionText(question);
 assert.equal(Buffer.byteLength(truncated,'utf8'),510);
 assert.equal(truncated,'字'.repeat(170));
 assert.equal(hostQuestionText('first\r\nsecond'),'first  second');
});

test('long card validates the exact host-rendered truncation and call identity',()=>{
 const {acceptReply,hostQuestionText}=require('../src/action-approval.cjs');
 const question='Allow this controlled child operation once '+ '字'.repeat(180);const record={digest:'a'.repeat(64),eventId:'evt_00000000-0000-0000-0000-000000000000',questionPrefix:'prefix',argv:['pnpm','install'],manager:{kind:'native',entry:{path:'manager'}},deniedActionId:'a',expires:Date.now()+30000,proposalExpires:Date.now()+30000,status:'question',question,questionCallId:'q',questionId:JSON.stringify(['request_user_input_async','q',0])};
 const answer=questionValue=>`<send_user_message_question_reply>\n${JSON.stringify([{questionItemId:record.questionId,question:questionValue,answer:'Allow this operation once'}])}\n</send_user_message_question_reply>`;
 acceptReply(record,answer(hostQuestionText(question).slice(0,-1)));assert.equal(record.status,'question');
 acceptReply(record,answer(hostQuestionText(question)));assert.equal(record.status,'approved');
});

test('unsupported fields and credential-like arguments do not enter the visible approval question',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'sts-private-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));const opt={dataDir:dir},base={session_id:'private',turn_id:'t',cwd:process.cwd()};
 handleHook({...base,hook_event_name:'UserPromptSubmit',prompt:'$stop-that-shit change deps=ask -- work'},opt);
 for(const input of [{command:'pnpm install --offline',environment:{SECRET:'private'}},{command:'npm install --token=private'}]){
  const denied=handleHook({...base,hook_event_name:'PreToolUse',tool_name:'Bash',tool_use_id:'a',tool_input:input},opt);
  assert.match(denied.hookSpecificOutput.permissionDecisionReason,/DEPENDENCY_NOT_AUTHORIZED/);
  assert.doesNotMatch(denied.hookSpecificOutput.permissionDecisionReason,/Approval question:|private/);
 }
});

test('hook rejects invalid approval cards and acknowledges an exact user decision', t => {
  const { spawnSync } = require('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-card-feedback-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const base = { session_id: 'feedback', turn_id: 't', cwd: process.cwd() };
  const call = (event, extra) => {
    const result = spawnSync(process.execPath, [path.join(__dirname, '../hooks/stop-that-shit.cjs')], {
      input: JSON.stringify({ ...base, hook_event_name: event, ...extra }),
      env: { ...process.env, PLUGIN_DATA: dir, STS_RUNTIME_DATA: dir }, encoding: 'utf8'
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout ? JSON.parse(result.stdout) : null;
  };
  const pre = (id, tool_name, tool_input) => call('PreToolUse', { tool_name, tool_use_id: id, tool_input });
  call('UserPromptSubmit', { prompt: '$stop-that-shit change deps=ask -- task' });
  const input = { command: 'pnpm install --offline --frozen-lockfile --ignore-scripts' };
  const denial = pre('original', 'Bash', input);
  const match = /Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(denial.hookSpecificOutput.permissionDecisionReason);
  assert.ok(match);
  const proposalEvent = /evt_[0-9a-f-]{36}/.exec(match[1])[0];
  const unbound = pre('unbound', 'request_user_input_async', { questions: [{ title: `Approve ${proposalEvent}?`, options: [match[2], match[3]] }] });
  assert.equal(unbound.hookSpecificOutput.permissionDecision, 'deny');
  const makeQuestion = directory => match[1].replace('<absolute canonical directory>', directory);
  const invalid = pre('bad', 'request_user_input_async', { questions: [{ title: makeQuestion('relative'), options: [match[2], match[3]] }] });
  assert.equal(invalid.hookSpecificOutput.permissionDecision, 'deny');
  const question = makeQuestion(fs.realpathSync(process.cwd()));
  assert.equal(pre('q', 'request_user_input_async', { questions: [{ title: question, options: [match[2], match[3]] }] }), null);
  const reply = answer => `<send_user_message_question_reply>\n${JSON.stringify([{ questionItemId: JSON.stringify(['request_user_input_async', 'q', 0]), question, answer }])}\n</send_user_message_question_reply>`;
  const acknowledged = call('UserPromptSubmit', { prompt: reply(match[2]) });
  assert.match(acknowledged.hookSpecificOutput.additionalContext, /one-time approval.*available/i);
  assert.match(acknowledged.hookSpecificOutput.additionalContext, /deps=ask/);
  const duplicate = pre('q2', 'request_user_input_async', { questions: [{ title: question, options: [match[2], match[3]] }] });
  assert.equal(duplicate.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(pre('retry', 'Bash', input).hookSpecificOutput.permissionDecision, 'allow');

  base.session_id = 'denied-feedback';
  call('UserPromptSubmit', { prompt: '$stop-that-shit change deps=ask -- task' });
  const next = pre('original', 'Bash', input);
  const nextMatch = /Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(next.hookSpecificOutput.permissionDecisionReason);
  const nextQuestion = nextMatch[1].replace('<absolute canonical directory>', fs.realpathSync(process.cwd()));
  assert.equal(pre('q', 'request_user_input_async', { questions: [{ title: nextQuestion, options: [nextMatch[2], nextMatch[3]] }] }), null);
  const deniedReply = `<send_user_message_question_reply>\n${JSON.stringify([{ questionItemId: JSON.stringify(['request_user_input_async', 'q', 0]), question: nextQuestion, answer: nextMatch[3] }])}\n</send_user_message_question_reply>`;
  const deniedAck = call('UserPromptSubmit', { prompt: deniedReply });
  assert.match(deniedAck.hookSpecificOutput.additionalContext, /one-time approval.*denied/i);
  assert.match(pre('retry', 'Bash', input).hookSpecificOutput.permissionDecisionReason, /DEPENDENCY_NOT_AUTHORIZED/);

  base.session_id = 'expired-feedback';
  call('UserPromptSubmit', { prompt: '$stop-that-shit change deps=ask -- task' });
  const expired = pre('original', 'Bash', input);
  const expiredMatch = /Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(expired.hookSpecificOutput.permissionDecisionReason);
  const { readState, writeState } = require('../src/state.cjs');
  const state = readState(base.session_id, dir);
  state.actionApproval.proposalExpires = Date.now() - 1;
  writeState(base.session_id, state, dir);
  const expiredQuestion = expiredMatch[1].replace('<absolute canonical directory>', fs.realpathSync(process.cwd()));
  assert.equal(pre('q', 'request_user_input_async', { questions: [{ title: expiredQuestion, options: [expiredMatch[2], expiredMatch[3]] }] }).hookSpecificOutput.permissionDecision, 'deny');
  const expiredEvent = /evt_[0-9a-f-]{36}/.exec(expiredQuestion)[0];
  assert.equal(pre('expired-unbound', 'request_user_input_async', { questions: [{ title: `Approve ${expiredEvent}?`, options: [expiredMatch[2], expiredMatch[3]] }] }).hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(pre('ordinary', 'request_user_input_async', { questions: [{ title: 'Which option?', options: ['A', 'B'] }] }), null);
  const expiredReply = `<send_user_message_question_reply>\n${JSON.stringify([{ questionItemId: JSON.stringify(['request_user_input_async', 'q', 0]), question: expiredQuestion, answer: expiredMatch[2] }])}\n</send_user_message_question_reply>`;
  assert.match(call('UserPromptSubmit', { prompt: expiredReply }).hookSpecificOutput.additionalContext, /No one-time approval was accepted/);
});

test('asynchronous approval has a 24-hour reply window and 10-minute consumption window', () => {
  const { acceptReply, live } = require('../src/action-approval.cjs');
  const now = Date.now();
  const question = 'Allow this controlled child operation once before a known UTC deadline: example';
  const makeRecord = age => ({
    digest: 'a'.repeat(64), eventId: 'evt_00000000-0000-0000-0000-000000000000',
    questionPrefix: 'prefix', question, questionId: 'question-id', questionCallId: 'q', deniedActionId: 'a',
    argv: ['pnpm', 'install'], manager: { kind: 'native', entry: { path: 'manager' } },
    targetCwd: 'target', status: 'question', expires: now - age + 10 * 60 * 1000,
    proposalExpires: now - age + 24 * 60 * 60 * 1000
  });
  const reply = `<send_user_message_question_reply>\n${JSON.stringify([{questionItemId:'question-id',question,answer:'Allow this operation once'}])}\n</send_user_message_question_reply>`;
  for (const age of [67 * 60 * 1000, 23 * 60 * 60 * 1000 + 59 * 60 * 1000]) {
    const record = makeRecord(age);
    assert.equal(acceptReply(record, reply, now).status, 'approved');
    assert.equal(record.expires, now + 10 * 60 * 1000);
    assert.equal(live(record, now + 10 * 60 * 1000 + 1), false);
  }
  const expired = makeRecord(24 * 60 * 60 * 1000 + 1);
  assert.equal(acceptReply(expired, reply, now).status, 'unavailable');
  assert.equal(expired.status, 'question');
});

test('approval deadline is rendered in UTC across midnight', t => {
  const { newPending } = require('../src/action-approval.cjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-deadline-'));
  const oldPath = process.env.PATH;
  t.after(() => { process.env.PATH = oldPath; fs.rmSync(root, { recursive: true, force: true }); });
  const entry = path.join(root, 'node_modules', 'pnpm', 'bin', 'pnpm.cjs');
  fs.mkdirSync(path.dirname(entry), { recursive: true });
  fs.writeFileSync(entry, '');
  process.env.PATH = root;
  const event = { sessionId: 'deadline', action: { id: 'a', name: 'Bash', cwd: root, input: { command: 'pnpm install --offline' } } };
  const start = Date.parse('2030-01-01T23:59:00.000Z');
  const record = newPending(event, 'evt_00000000-0000-0000-0000-000000000000', start);
  assert.match(record.questionPrefix, /Reply by 2030-01-02T23:59:00\.000Z/);
  assert.match(record.questionPrefix, /within 10 minutes after your reply/);
});

test('unsupported dependency syntax does not instruct a session-wide policy change', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-unsupported-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const options = { dataDir: dir };
  const base = { session_id: 'unsupported', turn_id: 't', cwd: process.cwd() };
  handleHook({ ...base, hook_event_name: 'UserPromptSubmit', prompt: '$stop-that-shit change deps=ask -- task' }, options);
  const denied = handleHook({ ...base, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_use_id: 'a', tool_input: { command: 'pnpm install && echo done' } }, options);
  const reason = denied.hookSpecificOutput.permissionDecisionReason;
  assert.match(reason, /DEPENDENCY_NOT_AUTHORIZED/);
  assert.doesNotMatch(reason, /deps=allow/);
  assert.match(reason, /single direct static dependency command/);
});

test('native reply arrays authorize the unique matching question and reject duplicate IDs', t => {
  const { spawnSync } = require('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-reply-array-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const base = { session_id: 'array', turn_id: 't', cwd: process.cwd() };
  const call = (event, extra) => {
    const result = spawnSync(process.execPath, [path.join(__dirname, '../hooks/stop-that-shit.cjs')], {
      input: JSON.stringify({ ...base, hook_event_name: event, ...extra }),
      env: { ...process.env, PLUGIN_DATA: dir, STS_RUNTIME_DATA: dir }, encoding: 'utf8'
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout ? JSON.parse(result.stdout) : null;
  };
  const pre = (id, tool_name, tool_input) => call('PreToolUse', { tool_name, tool_use_id: id, tool_input });
  const input = { command: 'pnpm install --offline --frozen-lockfile --ignore-scripts' };
  function prepare(session) {
    base.session_id = session;
    call('UserPromptSubmit', { prompt: '$stop-that-shit change deps=ask -- task' });
    const denied = pre('original', 'Bash', input);
    const match = /Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(denied.hookSpecificOutput.permissionDecisionReason);
    const question = match[1].replace('<absolute canonical directory>', fs.realpathSync(process.cwd()));
    assert.equal(pre('q', 'request_user_input_async', { questions: [{ title: question, options: [match[2], match[3]] }] }), null);
    return { questionItemId: JSON.stringify(['request_user_input_async', 'q', 0]), question, answer: match[2] };
  }
  const approved = prepare('array-one');
  const other = { questionItemId: 'other', question: 'Other question?', answer: 'Other answer' };
  const ack = call('UserPromptSubmit', { prompt: `<send_user_message_question_reply>\n${JSON.stringify([other, approved])}\n</send_user_message_question_reply>` });
  assert.match(ack.hookSpecificOutput.additionalContext, /one-time approval.*available/i);
  assert.equal(pre('retry', 'Bash', input).hookSpecificOutput.permissionDecision, 'allow');
  const duplicate = prepare('array-duplicate');
  const rejected = call('UserPromptSubmit', { prompt: `<send_user_message_question_reply>\n${JSON.stringify([duplicate, duplicate])}\n</send_user_message_question_reply>` });
  assert.match(rejected.hookSpecificOutput.additionalContext, /No one-time approval was accepted/);
  assert.match(pre('retry', 'Bash', input).hookSpecificOutput.permissionDecisionReason, /DEPENDENCY_NOT_AUTHORIZED/);
});

test('approved retry is denied with a clear reason when the system launcher is unavailable', { skip: process.platform !== 'win32' }, t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-launcher-unavailable-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const options = { dataDir: dir };
  const base = { session_id: 'launcher-unavailable', turn_id: 't', cwd: process.cwd() };
  const prompt = text => handleHook({ ...base, hook_event_name: 'UserPromptSubmit', prompt: text }, options);
  const pre = (id, tool_name, tool_input) => handleHook({ ...base, hook_event_name: 'PreToolUse', tool_name, tool_use_id: id, tool_input }, options);
  const input = { command: 'pnpm install --offline --frozen-lockfile --ignore-scripts' };
  prompt('$stop-that-shit change deps=ask -- task');
  const denied = pre('original', 'Bash', input);
  const match = /Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(denied.hookSpecificOutput.permissionDecisionReason);
  assert.ok(match);
  const question = match[1].replace('<absolute canonical directory>', fs.realpathSync(process.cwd()));
  assert.equal(pre('question', 'request_user_input_async', { questions: [{ title: question, options: [match[2], match[3]] }] }), null);
  prompt(`<send_user_message_question_reply>\n${JSON.stringify([{ questionItemId: JSON.stringify(['request_user_input_async', 'question', 0]), question, answer: match[2] }])}\n</send_user_message_question_reply>`);

  const previousRoot = process.env.SystemRoot;
  process.env.SystemRoot = path.join(dir, 'missing system root');
  let result;
  try { result = pre('retry', 'Bash', input); }
  finally {
    if (previousRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = previousRoot;
  }
  assert.equal(result.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(result.hookSpecificOutput.permissionDecisionReason, /APPROVED_LAUNCHER_UNAVAILABLE/);
  assert.match(result.hookSpecificOutput.permissionDecisionReason, /SystemRoot/);
});
