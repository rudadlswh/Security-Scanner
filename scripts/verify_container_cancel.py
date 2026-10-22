"""열린 루프백 연결이 있는 실제 컨테이너의 종료·정리를 검증한다.

자체 샘플의 미완성 health GET만 전달한다. 모델/CVE/변경 요청은 실행하지 않는다.
"""
import argparse
import asyncio
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from localcode_review_mcp.container_server import ContainerServer
from localcode_review_mcp.workspace import load_json, save_json, now
from smoke_mcp_assurance import tree_hashes
from urllib.parse import urlsplit


async def verify(config_path, output):
    output.mkdir(parents=True, exist_ok=False)
    cfg = load_json(config_path)
    profile = cfg['scan_profiles']['container']
    spec = profile['disposable_server']
    root = Path(spec['project_root']).resolve()
    before = tree_hashes(root)
    save_json(output / 'expectations.json', {
        'frozen_at': now(), 'image': spec['image'], 'open_connection_before_stop': True,
        'stop_timeout_seconds': 30, 'peer_eof': True, 'loopback_port_closed': True,
        'no_container_network_or_workspace_remaining': True, 'source_files': before})
    server = ContainerServer(spec, root, output,
        [cfg['http_targets'][key] for key in profile['http_target_ids']])
    report = {'started_at': now(), 'state': 'RUNNING', 'model_calls': 0,
              'external_cve_queries': 0, 'mutating_requests': 0}
    writer = None
    stopped = False
    try:
        await server.start()
        port = urlsplit(server.base).port
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        # 헤더 종결 빈 줄을 보내지 않아 연결을 열린 상태로 유지한다.
        writer.write(b'GET /health HTTP/1.1\r\nHost: localhost\r\n')
        await writer.drain()
        deadline = asyncio.get_running_loop().time() + 5
        while not server.relay.handlers and asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.05)
        assert server.relay.handlers
        await asyncio.sleep(0.3)
        report['open_connection_before_stop'] = bool(server.relay.handlers)
        assert report['open_connection_before_stop']
        started = asyncio.get_running_loop().time()
        await asyncio.wait_for(server.stop(), timeout=30)
        stopped = True
        report['stop_seconds'] = asyncio.get_running_loop().time() - started
        report['peer_eof'] = await asyncio.wait_for(reader.read(1), timeout=5) == b''
        assert report['peer_eof']
        try:
            _, unexpected = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), timeout=2)
        except OSError:
            report['loopback_port_closed'] = True
        else:
            unexpected.close()
            await unexpected.wait_closed()
            raise AssertionError('LISTENER_REMAINED')
        containers = await asyncio.to_thread(server.cli, 'ps', '--all', '--filter',
            'name=^/' + server.name + '$', '--format', '{{.Names}}')
        networks = await asyncio.to_thread(server.cli, 'network', 'ls', '--filter',
            'name=^' + server.network + '$', '--format', '{{.Name}}')
        report['cleanup_verified'] = not containers.strip() and not networks.strip() and not server.copy.exists()
        report['original_unchanged'] = before == tree_hashes(root)
        assert report['cleanup_verified'] and report['original_unchanged']
        report['state'] = 'PASSED'
    except BaseException as error:
        report.update(state='FAILED', error_type=type(error).__name__)
        raise
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        try:
            if not stopped:
                await server.stop()
        finally:
            report.update(server=server.metadata, finished_at=now())
            save_json(output / 'report.json', report)
    print('Actual active-connection cancellation, peer EOF, cleanup and original hashes passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(verify(args.config.resolve(), args.output.resolve()))
