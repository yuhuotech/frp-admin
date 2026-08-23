import { describe, expect, it } from 'vitest';
import { buildEnrollmentCommand } from './EnrollmentResultModal';

describe('buildEnrollmentCommand', () => {
  it('uses the actual agent CLI flags', () => {
    expect(buildEnrollmentCommand('one-time-token')).toBe("sudo frp-agent -config /etc/frp-agent/agent.yaml -enroll-token 'one-time-token' -enroll-ca /etc/frp-agent/agent-ca.pem");
  });

  it('shell-quotes token content', () => {
    expect(buildEnrollmentCommand("a'b")).toContain("'a'\"'\"'b'");
  });
});
