'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { directDependencyArguments } = require('./shell-analysis.cjs');
const { resolveManager } = require('./dependency-manager.cjs');

const PROPOSAL_TTL_MS = 24 * 60 * 60 * 1000;
const PERMIT_TTL_MS = 10 * 60 * 1000;
const YES = 'Allow this operation once';
const NO = 'Deny this operation';
const PROPOSAL_PREFIX = 'Allow this controlled child operation once';

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]));
}

function digest(event) {
  const action = event.action;
  if (!action || !['Bash', 'exec_command', 'shell_command'].includes(action.name)
      || !action.id || Buffer.byteLength(action.id, 'utf8') > 256
      || !action.cwd || !action.input || typeof action.input.command !== 'string') return null;
  if (!directDependencyArguments(action.input.command) || /[\r\n]/.test(action.input.command)) return null;
  const bound = stable({ session: event.sessionId, tool: action.name, input: action.input, cwd: action.cwd });
  return crypto.createHash('sha256').update(JSON.stringify(bound)).digest('hex');
}

function newPending(event, eventId, now = Date.now()) {
  const actionDigest = digest(event);
  if (!actionDigest || !eventId) return null;
  const argv = directDependencyArguments(event.action.input.command);
  // Do not place likely credentials or arbitrary environment fields in a user-visible question.
  if (Object.keys(event.action.input).some(key => key !== 'command')
      || argv.some(value => /(?:https?:|password|token|secret|api[_-]?key|authorization)/i.test(value))) return null;
  const manager = resolveManager(argv[0]);
  if (!manager) return null;
  const proposalExpires = now + PROPOSAL_TTL_MS;
  const questionPrefix = `${PROPOSAL_PREFIX}. Reply by ${new Date(proposalExpires).toISOString()}; if allowed, run once within 10 minutes after your reply: ${JSON.stringify(argv)} using ${JSON.stringify(manager.launchPath || manager.entry.path)} (${eventId}) in directory: `;
  if (Buffer.byteLength(questionPrefix, 'utf8') > 8192) return null;
  return { digest: actionDigest, eventId, questionPrefix, argv, manager,
    deniedActionId: event.action.id, expires: proposalExpires, proposalExpires, status: 'pending' };
}

function live(record, now = Date.now()) {
  return record && typeof record === 'object'
    && /^[a-f0-9]{64}$/.test(record.digest || '')
    && /^evt_[0-9a-f-]{36}$/.test(record.eventId || '')
    && typeof record.questionPrefix === 'string' && Buffer.byteLength(record.questionPrefix, 'utf8') <= 8192
    && Array.isArray(record.argv) && record.argv.every(arg => typeof arg === 'string')
    && record.manager && ['node', 'native'].includes(record.manager.kind)
    && record.manager.entry && typeof record.manager.entry.path === 'string'
    && (record.manager.kind !== 'node' || record.manager.executable && typeof record.manager.executable.path === 'string')
    && (record.status === 'pending' || typeof record.question === 'string' && Buffer.byteLength(record.question, 'utf8') <= 8192)
    && typeof record.deniedActionId === 'string' && record.deniedActionId.length > 0
    && (record.status === 'pending' || typeof record.questionId === 'string'
      && typeof record.questionCallId === 'string' && /^[A-Za-z0-9_-]{1,256}$/.test(record.questionCallId))
    && Number.isSafeInteger(record.proposalExpires) && Number.isSafeInteger(record.expires)
    && (['pending', 'question'].includes(record.status) ? record.proposalExpires : record.expires) > now
    && ['pending', 'question', 'approved', 'issued', 'consumed'].includes(record.status);
}

function isProposalQuestion(action, record) {
  const questions = action.input?.questions;
  return Array.isArray(questions) && questions.some(question =>
    typeof question?.title === 'string' && (question.title.startsWith(PROPOSAL_PREFIX)
      || record && typeof record.eventId === 'string' && question.title.includes(record.eventId)));
}

function registerQuestion(record, action) {
  if (!live(record) || record.status !== 'pending' || !action.id
      || !/^[A-Za-z0-9_-]{1,256}$/.test(action.id) || action.name !== 'request_user_input_async') return false;
  const questions = action.input?.questions;
  if (!Array.isArray(questions) || questions.length !== 1 || typeof questions[0]?.title !== 'string'
      || !questions[0].title.startsWith(record.questionPrefix) || !questions[0].title.endsWith('?')
      || JSON.stringify(questions[0]?.options) !== JSON.stringify([YES, NO])
      || Object.keys(action.input).length !== 1
      || Object.keys(questions[0]).some(key => !['title', 'options'].includes(key))) return false;
  const requested = questions[0].title.slice(record.questionPrefix.length, -1);
  if (!path.isAbsolute(requested) || /[\x00-\x1f\x7f]/.test(requested)) return false;
  let actual;
  try {
    actual = fs.realpathSync(requested);
    if (!fs.statSync(actual).isDirectory()) return false;
  } catch { return false; }
  if (Buffer.byteLength(questions[0].title, 'utf8') > 8192) return false;
  record.question = questions[0].title;
  record.requestedCwd = requested;
  record.targetCwd = actual;
  record.questionCallId = action.id;
  record.questionId = JSON.stringify(['request_user_input_async', action.id, 0]);
  record.status = 'question';
  return true;
}

function hostQuestionText(question) {
  let used = 0;
  let result = '';
  for (const char of question) {
    const size = Buffer.byteLength(char, 'utf8');
    if (used + size > 512) break;
    used += size;
    result += char;
  }
  return result.replace(/[\r\n]/g, ' ');
}

function acceptReply(record, text, now = Date.now()) {
  const match = /^<send_user_message_question_reply>\s*([\s\S]*?)\s*<\/send_user_message_question_reply>$/.exec(text);
  if (!match) return null;
  let data;
  try { data = JSON.parse(match[1]); } catch { return null; }
  if (!Array.isArray(data)) return null;
  const related = data.some(item => item && typeof item === 'object' && !Array.isArray(item)
    && (typeof item.question === 'string' && item.question.startsWith(PROPOSAL_PREFIX)
      || record && item.questionItemId === record.questionId));
  if (!related) return null;
  if (!live(record, now) || record.status !== 'question' || typeof record.questionId !== 'string') return { status: 'unavailable' };
  if (data.length > 32 || data.some(item => !item || typeof item !== 'object' || Array.isArray(item)
      || Object.keys(item).sort().join(',') !== 'answer,question,questionItemId'
      || !['questionItemId', 'question', 'answer'].every(key => typeof item[key] === 'string'))) return { status: 'mismatch' };
  const matches = data.filter(item => item.questionItemId === record.questionId);
  if (matches.length !== 1 || data.some(item => item.questionItemId !== record.questionId && item.question.startsWith(PROPOSAL_PREFIX))) return { status: 'mismatch' };
  const item = matches[0];
  if (item.question !== record.question && item.question !== hostQuestionText(record.question)) return { status: 'mismatch' };
  if (item.answer === YES) {
    record.status = 'approved';
    record.expires = now + PERMIT_TTL_MS;
    return { status: 'approved', eventId: record.eventId, targetCwd: record.targetCwd };
  }
  if (item.answer === NO) {
    record.status = 'consumed';
    return { status: 'denied', eventId: record.eventId };
  }
  return { status: 'mismatch' };
}

module.exports = { YES, NO, digest, newPending, live, isProposalQuestion, registerQuestion, acceptReply, hostQuestionText };
