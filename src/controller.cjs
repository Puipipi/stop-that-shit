'use strict';

const { DEFAULT_AGENT_LIMIT, parseContractPrompt } = require('./contracts.cjs');
const { SHELL_ANALYSIS_REASONS, isShellAnalysisReason, assertControlEvent, supportsLifecycleFacts } = require('./control-protocol.cjs');
const { inspectDelegation, applyDelegationFact } = require('./delegation-state.cjs');
const { decide } = require('./decision.cjs');
const { readRuntime, recordDecision } = require('./runtime-audit.cjs');
const { recordAnnotation } = require('./runtime-annotations.cjs');
const { readState, recoveryState, updateSession, dataRoot } = require('./state.cjs');
const path = require('node:path');
const crypto = require('node:crypto');
const approval = require('./action-approval.cjs');
const { buildRunnerCommand } = require('./runner-command.cjs');
const { bindingForRecord, createHandoff, handoffAvailable, withCoordinationLock } = require('./dependency-handoff.cjs');
// Keep the executable helper in the hook's statically discoverable dependency graph.
require('./dependency-runner.cjs');

function none() {
  return { kind: 'none' };
}

function context(text) {
  return { kind: 'context', text };
}

function coordinatedUpdate(event, options, update) {
  // The runner shares this temp-root lock while claiming its one-time handoff.
  // Hook writers take it before the private ledger lock so policy changes and
  // runner claims have a single ordering without making the runner write private state.
  return withCoordinationLock(event.sessionId, options.dataDir,
    () => updateSession(event.sessionId, options.dataDir, update));
}

function contractFields(contract, summary) {
  const limit = Number.isSafeInteger(contract.agentBudget) && contract.agentBudget >= 0 ? contract.agentBudget : DEFAULT_AGENT_LIMIT;
  return `mode=${contract.mode}; agents=${summary.reservedUpperBound}/${limit} reserved${summary.unresolvedReasons.length ? '; count unproven' : ''}; hash=${contract.hashPolicy || 'deny'}; deps=${contract.dependencyPolicy || 'ask'}; files=${Array.isArray(contract.allowedPaths) ? contract.allowedPaths.join('|') : 'unbounded'}.`;
}

function contractContext(contract, delegation = {}, phase = 'active', directiveWarning = null, storageError = null) {
  if (contract.source === 'recovery' && storageError) return `${storageError.code}: ${storageError.message}`;
  if (contract.source === 'recovery') return 'STATE_DAMAGED: the saved contract is unavailable. Read-only recovery is active. Restore a known-good backup or start a new host session; the damaged file is preserved.';
  if (typeof delegation === 'string') {
    phase = delegation;
    delegation = {};
  }
  if (contract.level === 'off') {
    return [
      directiveWarning && directiveWarning.message ? `Warning: ${directiveWarning.message}` : null,
      'Stop That Shit is disabled for this session. No plugin decision is being enforced.'
    ].filter(Boolean).join(' ');
  }
  if (contract.mode === 'unconfirmed') {
    return [
      directiveWarning && directiveWarning.message ? `Warning: ${directiveWarning.message}` : null,
      'Stop That Shit is in watch-only mode because no task mode is confirmed.',
      'Use $stop-that-shit review for read-only work, or change for implementation. The default fast path relies on the Stop Ladder and does not claim a full machine contract.',
      'Do not claim that mutations are being blocked until a mode is confirmed.'
    ].filter(Boolean).join(' ');
  }

  return [
    directiveWarning && directiveWarning.message ? `Warning: ${directiveWarning.message}` : null,
    `Stop That Shit (${phase}): ${contractFields(contract, inspectDelegation(delegation))}`,
    'Stop Ladder: Is it requested? Is it necessary? What reachable evidence proves that? Would omission fail the current acceptance?',
    'Report real findings even when implementation is not authorized.',
    'Before expanding scope, name reachable evidence, failure if omitted, and the fact that changes the next action.',
    'Harness interception coverage is a guardrail, not a security boundary.'
  ].filter(Boolean).join(' ');
}

const FAMILY_NAMES = { I: 'INTENT', H: 'HASH', S: 'SCOPE', T: 'THRASH' };

function activeControlState(contract) {
  if (contract.level === 'off') return 'OFF';
  return contract.level === 'watch' ? 'OBSERVING' : 'ARMED';
}

function decisionMessage(result, contract, event, responseOutcome, analysisReason) {
  const observing = responseOutcome === 'context_returned';
  const executionDenial = responseOutcome === 'execution_denial_returned';
  const lines = [
    `${observing ? 'WATCH' : 'STOP'} / ${FAMILY_NAMES[result.family] || result.family || 'CONTROL'}`,
    observing
      ? 'Guard returned context; it did not deny the action.'
      : executionDenial ? 'Guard returned a pre-execution denial.' : 'Guard returned permission deny.',
    `Reason: ${result.reasonCode}`,
    ...(result.explanation ? [`Detail: ${result.explanation}`] : []),
    `Code: ${result.family}/${result.reasonCode}`,
    `State: ${activeControlState(contract)} / ${contract.mode}`
  ];
  if (event) lines.push(`Event: ${event.eventId}`);
  if (result.nextStep) lines.push(`Next: ${result.nextStep}`);
  return lines.join('\n');
}

function runtimeCommand(prompt) {
  const match = /^(?:[ \t]*\r?\n)* {0,3}\$(?:stop-that-shit:)?stop-that-shit[ \t]+(status|runtime(?:[ \t]+all)?|explain[ \t]+(evt_[0-9a-f-]+)|label[ \t]+(evt_[0-9a-f-]+)[ \t]+(correct|incorrect|inconclusive))[ \t]*(?:\r?\n[ \t]*)*$/i.exec(prompt);
  if (!match) return null;
  const words = match[1].toLowerCase().split(/\s+/);
  return { name: words[0], all: words[1] === 'all', eventId: match[2] || match[3] || null, label: match[4] || null };
}

function runtimeSummaryText(runtime) {
  const { summary } = runtime;
  const labels = summary.labels;
  const lines = [
    'Stop That Shit runtime (host effect remains unobserved)',
    `Checked actions: ${summary.checkedActions}`,
    `Context responses: ${summary.contextResponses}`,
    `Permission-deny responses: ${summary.permissionDenyResponses}`
  ];
  if (summary.executionDenialResponses) {
    lines.push(`Execution-denial responses: ${summary.executionDenialResponses}`);
  }
  lines.push(
    `Labels: correct=${labels.correct}; incorrect=${labels.incorrect}; inconclusive=${labels.inconclusive}`,
    `Damaged records ignored: ${summary.damagedRecords}`
  );
  return lines.join('\n');
}

function handleRuntimeCommand(command, event, state, options) {
  if (command.name === 'status') {
    const summary = inspectDelegation(state.delegation);
    return context([
      'Stop That Shit status',
      `State: ${activeControlState(state.contract)} / ${state.contract.mode}`,
      contractFields(state.contract, summary),
      `Authority source: ${state.contract.source || 'unconfirmed'}`,
      ...(state.storageError ? [`${state.storageError.code}: ${state.storageError.message}`] : []),
      ...(state.directiveError ? [`Directive error: ${state.directiveError.code}: ${state.directiveError.message}`] : []),
      ...(summary.unresolvedReasons.length
        ? [`Unresolved activity: ${summary.unresolvedReasons.join(', ')}. A confirmed completion or a new host session is required; do not reset the ledger.`] : []),
      'Host effect: unobserved',
      'Use runtime for checked-action and Guard-response counts.'
    ].join('\n'));
  }
  if (command.name === 'runtime') {
    const query = command.all ? {} : { sessionId: event.sessionId };
    return context(runtimeSummaryText(readRuntime(query, options)));
  }
  const runtime = readRuntime({ eventId: command.eventId }, options);
  if (runtime.events.length === 0) return context(`Stop That Shit runtime event not found: ${command.eventId}`);
  if (command.name === 'label') {
    const annotation = recordAnnotation(command.eventId, command.label, options);
    return context(annotation
      ? `Stop That Shit label recorded: ${command.eventId} = ${command.label}`
      : `Stop That Shit could not record label for ${command.eventId}.`);
  }
  const found = runtime.events[0];
  return context([
    `Stop That Shit event ${found.eventId}`,
    `State: ${found.controlState.toUpperCase()} / ${found.contract.mode}`,
    `Action: ${found.action.toolName} (${found.action.mutability}); paths=${found.action.pathCount}`,
    ...(isShellAnalysisReason(found.action.analysisReason)
      ? [`Analysis: ${SHELL_ANALYSIS_REASONS[found.action.analysisReason]}`] : []),
    `Decision: ${found.decision.policyOutcome} / ${found.decision.reasonCode}`,
    `Response: ${found.decision.responseOutcome}`,
    `Host effect: ${found.decision.hostEffect}`,
    `Label: ${found.label || 'unlabeled'}`
  ].join('\n'));
}

function handlePrompt(event, state) {
  if (state.storageError) return context(`${state.storageError.code}: ${state.storageError.message}`);
  const parsed = parseContractPrompt(event.prompt, state.contract);
  if (parsed.error) {
    state.directiveError = parsed.error;
    state.directiveWarning = null;
    state.lastPromptContext = null;
    return { kind: 'prompt-error', error: parsed.error, message: parsed.error.message };
  }
  state.contract = parsed.contract;
  const reply = approval.acceptReply(state.actionApproval, event.prompt);
  if (state.contract.mode !== 'change' || state.contract.dependencyPolicy !== 'ask' || state.contract.level !== 'guard') {
    state.actionApproval = null;
    if (reply) reply.status = 'unavailable';
  }
  if (parsed.directive || parsed.correction) state.directiveError = null;
  if (parsed.directive || parsed.correction) state.directiveWarning = parsed.directive ? parsed.warning : null;
  const promptContext = contractContext(state.contract, state.delegation, 'active', parsed.warning || state.directiveWarning, state.storageError);
  const repeatedContext = state.lastPromptContext === promptContext;
  state.lastPromptContext = promptContext;
  if (reply) {
    const acknowledgment = reply.status === 'approved'
      ? `One-time approval is available for ${reply.eventId} in ${reply.targetCwd}. Retry the same operation; session deps=ask remains unchanged.`
      : reply.status === 'denied'
        ? `One-time approval for ${reply.eventId} was denied. No operation was authorized; session deps=ask remains unchanged.`
        : 'No one-time approval was accepted: the question is unavailable, expired or does not match. The dependency policy is unchanged.';
    return context(`${promptContext}\n${acknowledgment}`);
  }
  if (parsed.warning) return { ...context(promptContext), warning: parsed.warning };
  return repeatedContext ? none() : context(promptContext);
}

function handleApprovalAction(event, options) {
  let orphanedHandoff = null;
  try {
    const result = withCoordinationLock(event.sessionId, options.dataDir, () => updateSession(event.sessionId, options.dataDir, state => {
    if (state.storageError) return { kind: 'deny', message: state.storageError.message };
    const summary = inspectDelegation(state.delegation, { id: event.action.id });
    const action = { ...event.action, duplicateActionId: summary.duplicateActionId };
    let result = decide({ contract: state.contract, action, delegation: summary, state });
    let usedApproval = null;
    let rewrittenCommand = null;
    const record = state.actionApproval;
    if (approval.live(record) && record.status === 'issued'
        && !handoffAvailable(record.handoff, bindingForRecord(event.sessionId, record))) {
      record.status = 'consumed';
      delete record.ticket;
      delete record.handoff;
    }
    if (result.reasonCode === 'DEPENDENCY_NOT_AUTHORIZED' && state.contract.dependencyPolicy === 'ask'
        && state.contract.mode === 'change' && state.contract.level === 'guard' && approval.live(record)
        && ['approved', 'issued'].includes(record.status) && event.action.id !== record.deniedActionId
        && approval.digest(event) === record.digest) {
      const remaining = decide({ contract: state.contract, action: { ...action, dependencyIntent: false }, delegation: summary, state });
      if (remaining.outcome === 'allow') {
        const ticket = record.status === 'issued' ? record.ticket : crypto.randomBytes(32).toString('hex');
        try {
          rewrittenCommand = buildRunnerCommand({
            executable: process.execPath,
            runnerPath: path.join(__dirname, 'dependency-runner.cjs'),
            sessionId: event.sessionId,
            dataDir: dataRoot(options.dataDir),
            ticket
          });
          const handoff = record.status === 'issued' ? record.handoff
            : createHandoff(bindingForRecord(event.sessionId, record, ticket));
          if (record.status !== 'issued') orphanedHandoff = handoff;
          else if (!handoffAvailable(handoff, bindingForRecord(event.sessionId, record))) {
            throw new Error('The issued one-time handoff is unavailable; it cannot be recreated.');
          }
          record.status = 'issued';
          record.handoff = handoff;
          record.approvedAction = {
            mutability: action.mutability,
            analysisReason: action.analysisReason,
            hashIntent: Boolean(action.hashIntent),
            reachability: action.reachability,
            authorization: action.authorization,
            affectedPaths: action.affectedPaths,
            cwd: record.targetCwd,
            unboundedDelegation: Boolean(action.unboundedDelegation),
            delegationLifecycleUnproven: Boolean(action.delegationLifecycleUnproven)
          };
          record.issuedActionId = event.action.id;
          record.ticket = ticket;
          usedApproval = { eventId: record.eventId, questionCallId: record.questionCallId, consumed: false };
          result = remaining;
        } catch (error) {
          result = {
            outcome: 'deny_and_explain', family: 'S', reasonCode: 'APPROVED_LAUNCHER_UNAVAILABLE',
            explanation: error.message,
            nextStep: 'The one-time approval remains unused. Retry after restoring a verifiable system PowerShell launcher path.'
          };
        }
      }
    }
    if (result.outcome === 'allow' && ['request_user_input_async', 'request_user_input'].includes(event.action.name)
        && approval.isProposalQuestion(event.action, record || { eventId: state.expiredApprovalEventId })
        && !approval.registerQuestion(record, event.action)) {
      result = { outcome: 'deny_and_explain', family: 'S', reasonCode: 'APPROVAL_QUESTION_INVALID',
        explanation: 'The approval question is expired, already registered, or does not match the pending operation and an existing absolute directory.',
        nextStep: 'Request a fresh approval for the specific operation; do not display an unbound card.' };
    }
    const denied = ['deny_and_explain', 'require_user_approval'].includes(result.outcome);
    const responseOutcome = denied ? options.denialResponseOutcome || 'permission_deny_returned'
      : result.outcome === 'report_and_defer' ? 'context_returned' : 'none';
    const auditEvent = recordDecision({ sessionId: event.sessionId, action: event.action, contract: state.contract,
      delegation: state.delegation, decision: result, responseOutcome, approval: usedApproval }, options);
    let message;
    if (denied && result.reasonCode === 'DEPENDENCY_NOT_AUTHORIZED' && state.contract.dependencyPolicy === 'ask'
        && state.contract.mode === 'change' && state.contract.level === 'guard') {
      let pending = null;
      if (!approval.live(record) || record.status === 'consumed') {
        pending = approval.newPending(event, auditEvent && auditEvent.eventId);
        if (pending) { state.actionApproval = pending; state.expiredApprovalEventId = null; }
      } else if (record.status === 'pending' && approval.digest(event) === record.digest) {
        pending = record;
      }
      const nextStep = pending
        ? 'Submit the exact approval card below with the target directory. After an affirmative reply, retry this operation; the session remains deps=ask.'
        : approval.live(record) && record.status !== 'consumed'
          ? 'An approval is already bound to another action or is awaiting execution. Use the matching operation; the session remains deps=ask.'
          : 'A single direct static dependency command or supported PowerShell wrapper can be proposed as a controlled child and still requires a card. For diagnostic text use a supported literal write or file edit; do not execute an install.';
      message = decisionMessage({ ...result, nextStep }, state.contract, auditEvent, responseOutcome, event.action.analysisReason);
      if (pending) message += `\nApproval question: ${pending.questionPrefix}<absolute canonical directory>?\nApproval options: ${approval.YES} | ${approval.NO}`;
      else if (!approval.live(record) || record.status === 'consumed') message += '\nOne-time approval is unavailable for this operation or no safe package manager entry was found.';
    } else {
      message = decisionMessage(result, state.contract, auditEvent, responseOutcome, event.action.analysisReason);
    }
    if (denied) return { kind: 'deny', decision: result, eventId: auditEvent && auditEvent.eventId, message };
    if (rewrittenCommand) return { kind: 'rewrite', command: rewrittenCommand };
    return responseOutcome === 'context_returned' ? context(message) : none();
    }));
    orphanedHandoff = null;
    return result;
  } catch {
    // A failed private state commit must not leave a reusable orphan capability.
    if (orphanedHandoff) {
      try { require('./dependency-handoff.cjs').discardHandoff(orphanedHandoff); } catch {}
    }
    // A failed ledger lock or write cannot turn a guarded action into a fail-open call.
    return { kind: 'deny', message: 'Stop That Shit: approval state unavailable; action denied.' };
  }
}

function handleBeforeAction(event, options) {
  if (!options.recoveryError && event.host?.family === 'codex'
      && (event.action.name === 'request_user_input_async' || event.action.dependencyIntent)) {
    return handleApprovalAction(event, options);
  }
  if (!options.recoveryError && event.host?.family === 'codex' && event.action.name === 'request_user_input') {
    let snapshot = null;
    try { snapshot = readState(event.sessionId, options.dataDir); } catch {}
    const record = snapshot && (snapshot.actionApproval || { eventId: snapshot.expiredApprovalEventId });
    if (approval.isProposalQuestion(event.action, record) || approval.isProposalQuestion(event.action, null)) {
      return handleApprovalAction(event, options);
    }
  }
  const legacyDelegationProtocol = !supportsLifecycleFacts(event)
    && ['delegate', 'control', 'unknown'].includes(event.action.mutability);
  const changesDelegation = event.action.mutability === 'delegate'
    || event.action.delegationLifecycleUnproven || legacyDelegationProtocol;
  const delegationCount = event.action.mutability === 'delegate'
    ? (Number.isInteger(event.action.delegationCount) ? event.action.delegationCount : 1)
    : 0;
  const evaluate = (state) => {
    const action = {
      mutability: event.action.mutability,
      analysisReason: event.action.analysisReason,
      legacyDelegationProtocol,
      delegationCount,
      hashIntent: Boolean(event.action.hashIntent),
      reachability: event.action.reachability,
      authorization: event.action.authorization,
      affectedPaths: event.action.affectedPaths,
      cwd: event.action.cwd,
      dependencyIntent: Boolean(event.action.dependencyIntent),
      unboundedDelegation: Boolean(event.action.unboundedDelegation),
      delegationLifecycleUnproven: Boolean(event.action.delegationLifecycleUnproven)
    };
    const summary = inspectDelegation(state.delegation, { id: event.action.id });
    action.duplicateActionId = summary.duplicateActionId;
    const result = decide({ contract: state.contract, action, delegation: summary, state });
    if (changesDelegation && ['allow', 'report_and_defer'].includes(result.outcome)) {
      state.delegation = applyDelegationFact(state.delegation, {
        kind: 'accepted', id: event.action.id || 'legacy:unidentified', count: delegationCount,
        completionScope: event.action.completionScope,
        uncertainty: legacyDelegationProtocol ? 'legacy_protocol'
          : action.unboundedDelegation ? 'unbounded_execution'
          : action.delegationLifecycleUnproven ? 'unversioned_resume' : null
      });
    } else if (changesDelegation && summary.duplicateActionId) {
      // A later not-started event may describe this rejected attempt, not the
      // original pending execution that still owns the reservation.
      state.delegation = applyDelegationFact(state.delegation, { kind: 'duplicate_rejected', id: event.action.id });
    }
    return { state, result };
  };

  // Separate host processes can issue independent agent launches close together.
  // Serialize delegation reservations across Hook processes. Prompt updates
  // and completion handlers use the same lock; pure reads stay unlocked.
  const { state, result } = options.recoveryError
    ? evaluate(recoveryState(options.recoveryError))
    : changesDelegation
      ? coordinatedUpdate(event, options, evaluate)
      : evaluate(readState(event.sessionId, options.dataDir));

  const denied = result.outcome === 'deny_and_explain' || result.outcome === 'require_user_approval';
  const responseOutcome = denied
    ? options.denialResponseOutcome || 'permission_deny_returned'
    : result.outcome === 'report_and_defer' ? 'context_returned' : 'none';
  const auditEvent = recordDecision({
    sessionId: event.sessionId,
    action: { ...event.action, delegationCount },
    contract: state.contract,
    delegation: state.delegation,
    decision: result,
    responseOutcome
  }, options);

  if (denied) {
    return { kind: 'deny', decision: result, eventId: auditEvent && auditEvent.eventId, message: decisionMessage(result, state.contract, auditEvent, responseOutcome, event.action.analysisReason) };
  }
  if (responseOutcome === 'context_returned') {
    return context(decisionMessage(result, state.contract, auditEvent, responseOutcome, event.action.analysisReason));
  }
  return none();
}

function handleAfterAction(event, options) {
  if (event.action?.name === 'request_user_input') {
    if (event.host?.family !== 'codex') return none();
    try {
      const snapshot = readState(event.sessionId, options.dataDir);
      if (event.action.unanswered === true) {
        if (snapshot.storageError || !approval.nativeQuestionMatches(snapshot.actionApproval, event.action)) return none();
        return coordinatedUpdate(event, options, state => {
          if (!state.storageError && approval.nativeQuestionMatches(state.actionApproval, event.action)) {
            state.actionApproval = null;
          }
          return none();
        });
      }
      if (snapshot.storageError || !approval.nativeAnswerMatches(snapshot.actionApproval, event.action)) return none();
      return coordinatedUpdate(event, options, state => {
        if (!state.storageError) approval.acceptNativeAnswer(state.actionApproval, event.action);
        return none();
      });
    } catch {
      // An unavailable approval ledger leaves the proposal unapproved.
      return none();
    }
  }
  if (!supportsLifecycleFacts(event)) return none();
  return coordinatedUpdate(event, options, (state) => {
    // Only a declared facts adapter may report binding or completion. A false
    // async flag can be a request parameter and never proves children joined.
    const kind = event.action.lifecycle || (event.action.completed === true ? 'joined'
      : event.action.asyncLaunched === true ? 'running' : 'unknown');
    state.delegation = applyDelegationFact(state.delegation, {
      kind, id: event.action.id, agentId: event.action.agentId, agentAliases: event.action.agentAliases
    });
    for (const agentId of event.action.endedAgentIds || []) {
      state.delegation = applyDelegationFact(state.delegation, { kind: 'child_stopped', agentId });
    }
    return none();
  });
}

function handleLifecycleContext(event, options) {
  // An older adapter may borrow the current protocol number but still map stop
  // attempts to terminal events. Its facts cannot mutate the current ledger.
  if (!supportsLifecycleFacts(event) && event.kind !== 'session.start') return none();
  const update = (state) => {
    const fact = event.kind === 'subagent.start'
      ? { kind: 'child_started', agentId: event.agentId, agentAlias: event.agentAlias, reservationId: event.reservationId }
      : event.kind === 'subagent.stop' ? { kind: 'child_stopped', agentId: event.agentId }
      : { kind: event.allDelegationsStopped === true ? 'all_stopped' : 'unknown' };
    state.delegation = applyDelegationFact(state.delegation, fact);
    return context(contractContext(state.contract, state.delegation, 'active', state.directiveWarning, state.storageError));
  };
  // Ordinary session end carries no completion fact. Keep its context response
  // without waiting for another writer or rewriting state during shutdown.
  const readOnly = event.kind === 'session.start'
    || event.kind === 'session.end' && event.allDelegationsStopped !== true;
  return readOnly ? update(readState(event.sessionId, options.dataDir))
    : coordinatedUpdate(event, options, update);
}

function handleControlEvent(rawEvent, options = {}) {
  let event = assertControlEvent(rawEvent);
  if (event.action && event.action.id && event.sourceSessionId && event.sourceSessionId !== event.sessionId) {
    event = { ...event, action: { ...event.action, id: JSON.stringify([event.sourceSessionId, event.action.id]) } };
  }
  switch (event.kind) {
    case 'prompt.submit': {
      const command = runtimeCommand(event.prompt);
      return command
        ? handleRuntimeCommand(command, event, readState(event.sessionId, options.dataDir), options)
        : coordinatedUpdate(event, options, state => handlePrompt(event, state));
    }
    case 'action.before':
      return handleBeforeAction(event, options);
    case 'action.after':
      return handleAfterAction(event, options);
    case 'session.start':
    case 'subagent.start':
    case 'subagent.stop':
    case 'session.end':
      return handleLifecycleContext(event, options);
    default:
      return none();
  }
}

module.exports = { contractContext, handleControlEvent, runtimeCommand };
