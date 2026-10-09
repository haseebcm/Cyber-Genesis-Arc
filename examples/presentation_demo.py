"""Offline, repeatable five-minute demonstration of the H11 architecture."""
from h11_cga import CyberGenesisEngine, AIAgentGuardrailEngine, AIToolRequest, AIToolCategory


def main():
    engine = CyberGenesisEngine()
    healthy = engine.process_tick()
    assert healthy.permission == 1
    print(f'1. Authorized root: {healthy.status.value}, G={healthy.genesis_value:.4f}')
    attacked = engine.inject_attack('ransomware', .7)
    assert attacked.permission == 0
    print(f'2. Simulated ransomware: {attacked.status.value}, DR={attacked.dr_value:.4f}, CCI={attacked.cci_value:.4f}')
    print('3. Origin hypotheses:', ', '.join(h.name for h in attacked.origin_hypotheses))
    print('   Response recommendations:', ', '.join(a.action_type.value for a in attacked.recommended_actions[:3]))
    guard = AIAgentGuardrailEngine()
    guard.register_tool('read_public', AIToolCategory.FILE_READ, lambda path: 'public document', lambda p: p == {'path': '/public'})
    result = guard.execute_guarded(AIToolRequest('presenter', 'read_public', AIToolCategory.FILE_READ, {'path': '/public'}))
    print('4. Registered, authorized tool:', result)
    try:
        guard.execute_guarded(AIToolRequest('presenter', 'read_public', AIToolCategory.FILE_READ, {'path': '/secrets'}))
    except PermissionError:
        print('5. Unauthorized parameter blocked before execution')
    else:
        raise AssertionError('Policy failed')
    print('Simulation recovery changes model coordinates. Host remediation requires an external response integration.')


if __name__ == '__main__':
    main()
