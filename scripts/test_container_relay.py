"""Docker 없이 루프백 relay의 byte 투명성·명령 분리·취소/포트 경계를 실제 소켓으로 검증한다."""
import asyncio
import socket
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from localcode_review_mcp.container_relay import ContainerRelay,TUNNEL


class RelayTest(unittest.TestCase):
    def port(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));return sock.getsockname()[1]

    def test_binary_stream_and_credentials_are_data_not_command_arguments(self):
        async def run():
            relay=ContainerRelay('docker-fixed','lcr-fixed',self.port(),8080)
            original=asyncio.create_subprocess_exec;calls=[];processes=[]
            async def fake(*argv,**kwargs):
                calls.append(argv)
                code='import os\nwhile True:\n b=os.read(0,65536)\n if not b: break\n os.write(1,b)'
                process=await original(sys.executable,'-u','-c',code,**kwargs);processes.append(process);return process
            with patch('localcode_review_mcp.container_relay.asyncio.create_subprocess_exec',side_effect=fake):
                await relay.start()
                reader,writer=await asyncio.open_connection('127.0.0.1',relay.host_port)
                payload=b'Authorization: secret-token\r\n$(`not-code`)\x00'+bytes(range(256))
                writer.write(payload);await writer.drain()
                actual=await asyncio.wait_for(reader.readexactly(len(payload)),timeout=5)
                self.assertEqual(payload,actual)
                self.assertNotIn('secret-token',repr(calls))
                self.assertIn(TUNNEL,calls[0]);self.assertIn('8080',calls[0])
                self.assertNotIn('--publish',repr(calls))
                writer.close();await writer.wait_closed()
                await relay.stop()
                self.assertTrue(all(p.returncode is not None for p in processes))
                self.assertEqual(0,relay.metadata['active_connections'])
                self.assertFalse(relay.metadata['raw_logs_saved'])
        asyncio.run(run())

    def test_stop_cancels_open_connections_and_releases_exclusive_port(self):
        async def run():
            port=self.port();relay=ContainerRelay('docker-fixed','lcr-fixed',port,8080)
            original=asyncio.create_subprocess_exec;started=asyncio.Event();processes=[]
            async def fake(*argv,**kwargs):
                process=await original(sys.executable,'-u','-c','import sys;sys.stdin.buffer.read()',**kwargs)
                processes.append(process);started.set();return process
            with patch('localcode_review_mcp.container_relay.asyncio.create_subprocess_exec',side_effect=fake):
                await relay.start()
                reader,writer=await asyncio.open_connection('127.0.0.1',port)
                await asyncio.wait_for(started.wait(),5)
                await relay.stop()
                self.assertEqual(b'',await asyncio.wait_for(reader.read(),5))
                writer.close();await writer.wait_closed()
                self.assertEqual(0,len(relay.handlers))
                self.assertTrue(all(p.returncode is not None for p in processes))
            with socket.socket() as sock:sock.bind(('127.0.0.1',port))
        asyncio.run(run())

    def test_connection_limit_refuses_before_starting_another_process(self):
        async def run():
            relay=ContainerRelay('docker-fixed','lcr-fixed',self.port(),8080)
            with patch('localcode_review_mcp.container_relay.asyncio.create_subprocess_exec') as launch:
                await relay.start();relay.handlers.update(object() for _ in range(16))
                reader,writer=await asyncio.open_connection('127.0.0.1',relay.host_port)
                self.assertEqual(b'',await asyncio.wait_for(reader.read(),5));launch.assert_not_called()
                writer.close();await writer.wait_closed();relay.handlers.clear();await relay.stop()
        asyncio.run(run())

    def test_existing_listener_is_never_reused(self):
        async def run():
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));sock.listen()
                relay=ContainerRelay('docker-fixed','lcr-fixed',sock.getsockname()[1],8080)
                with self.assertRaises(OSError):await relay.start()
                await relay.stop()
        asyncio.run(run())


if __name__=='__main__':unittest.main()
