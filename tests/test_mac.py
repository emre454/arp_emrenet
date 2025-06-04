from unittest import mock
import importlib.util
import sys
import os
import types


def load_module():
    path = os.path.join(os.path.dirname(__file__), os.pardir, 'arp_emrenet.py')
    dummy_http = types.ModuleType('scapy.layers.http')
    dummy_http.HTTPRequest = object
    dummy_all = types.ModuleType('scapy.all')
    dummy_layers = types.ModuleType('scapy.layers')
    dummy_layers.http = dummy_http
    dummy_root = types.ModuleType('scapy')
    dummy_root.all = dummy_all

    with mock.patch.dict(sys.modules, {
        'scapy': dummy_root,
        'scapy.all': dummy_all,
        'scapy.layers': dummy_layers,
        'scapy.layers.http': dummy_http,
    }):
        spec = importlib.util.spec_from_file_location('arp_emrenet', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules['arp_emrenet'] = module
        spec.loader.exec_module(module)
        return module


def test_mac_degistir_calls_ifconfig():
    arp_emrenet = load_module()
    with mock.patch('subprocess.call') as mock_call:
        arp_emrenet.mac_degistir('eth0', '00:11:22:33:44:55')
        expected_calls = [
            mock.call(["ifconfig", 'eth0', "down"]),
            mock.call(["ifconfig", 'eth0', "hw", "ether", '00:11:22:33:44:55']),
            mock.call(["ifconfig", 'eth0', "up"]),
        ]
        assert mock_call.call_args_list == expected_calls
        assert mock_call.call_count == 3
