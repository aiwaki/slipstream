"""Session-owned macOS HTTPS proxy overlay, with no persistent preference edits.

configd removes temporary values when this process dies. Existing State keys
are never replaced; persistent Setup values retain precedence. Closing the
session reveals the original configuration, including any concurrent edits.
"""
import ctypes as C
import plistlib
import re
import threading


class DynamicStore:
    def __init__(self):
        self.cf = C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sc = C.CDLL('/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration')
        pointer = C.c_void_p
        signatures = (
            (self.cf, 'CFRelease', None, [pointer]),
            (self.cf, 'CFDataCreate', pointer, [pointer, pointer, C.c_long]),
            (self.cf, 'CFDataGetLength', C.c_long, [pointer]),
            (self.cf, 'CFDataGetBytePtr', pointer, [pointer]),
            (self.cf, 'CFPropertyListCreateWithData', pointer,
             [pointer, pointer, C.c_ulong, pointer, pointer]),
            (self.cf, 'CFPropertyListCreateData', pointer,
             [pointer, pointer, C.c_long, C.c_ulong, pointer]),
            (self.sc, 'SCDynamicStoreCreate', pointer, [pointer, pointer, pointer, pointer]),
            (self.sc, 'SCDynamicStoreCopyValue', pointer, [pointer, pointer]),
            (self.sc, 'SCDynamicStoreAddTemporaryValue', C.c_ubyte, [pointer, pointer, pointer]),
        )
        for library, name, result, args in signatures:
            fn = getattr(library, name)
            fn.restype, fn.argtypes = result, args
        name = self._encode('dev.slipstream.https-proxy')
        try:
            self.session = self.sc.SCDynamicStoreCreate(None, name, None, None)
        finally:
            self.cf.CFRelease(name)
        if not self.session:
            raise OSError('dynamic store session unavailable')

    def _encode(self, value):
        raw = plistlib.dumps(value)
        data = self.cf.CFDataCreate(None, raw, len(raw))
        try:
            result = self.cf.CFPropertyListCreateWithData(None, data, 0, None, None)
            if not result:
                raise ValueError('invalid property list')
            return result
        finally:
            self.cf.CFRelease(data)

    def get(self, key):
        ref = self._encode(key)
        try:
            value = self.sc.SCDynamicStoreCopyValue(self.session, ref)
        finally:
            self.cf.CFRelease(ref)
        if not value:
            return None
        data = None
        try:
            data = self.cf.CFPropertyListCreateData(None, value, 100, 0, None)
            if not data:
                raise ValueError('dynamic store value is not a property list')
            return plistlib.loads(C.string_at(self.cf.CFDataGetBytePtr(data),
                                             self.cf.CFDataGetLength(data)))
        finally:
            if data:
                self.cf.CFRelease(data)
            self.cf.CFRelease(value)

    def add(self, key, value):
        key_ref, value_ref = self._encode(key), self._encode(value)
        try:
            return bool(self.sc.SCDynamicStoreAddTemporaryValue(self.session, key_ref, value_ref))
        finally:
            self.cf.CFRelease(key_ref)
            self.cf.CFRelease(value_ref)

    def close(self):
        if self.session:
            self.cf.CFRelease(self.session)
            self.session = None


_ACTIVE = ('HTTPEnable', 'HTTPSEnable', 'SOCKSEnable',
           'ProxyAutoConfigEnable', 'ProxyAutoDiscoveryEnable')
_PREFERENCE_KEYS = ('HTTPSEnable', 'HTTPSProxy', 'HTTPSPort',
                    'ProxyAutoConfigEnable', 'ProxyAutoDiscoveryEnable', 'SOCKSEnable')


def _has_active_proxy(value):
    if isinstance(value, dict):
        return (any(value.get(key) for key in _ACTIVE)
                or any(_has_active_proxy(item) for item in value.values()))
    if isinstance(value, list):
        return any(_has_active_proxy(item) for item in value)
    return False


class ProxyLease:
    def __init__(self, port, store_factory=DynamicStore):
        self.port = port
        self.store_factory = store_factory
        self.store = None
        self.keys = {}
        self.lock = threading.RLock()

    def start(self):
        with self.lock:
            self._start()

    def _start(self):
        if self.store is not None:
            raise RuntimeError('proxy lease already started')
        self.keys = {}
        store = self.store_factory()
        try:
            global_proxy = store.get('State:/Network/Global/Proxies') or {}
            if _has_active_proxy(global_proxy):
                raise ValueError('external proxy already active')
            services = set()
            for family in ('IPv4', 'IPv6'):
                service = (store.get('State:/Network/Global/' + family) or {}).get('PrimaryService')
                if service and re.fullmatch(r'[A-Za-z0-9-]{1,128}', service):
                    services.add(service)
            if not services:
                raise ValueError('no primary network service')
            for service in sorted(services):
                suffix = '/Network/Service/' + service + '/Proxies'
                setup = store.get('Setup:' + suffix) or {}
                # Setup takes precedence over State, even when explicitly off.
                # Never silently change or bypass an existing HTTPS/PAC choice.
                if any(key in setup for key in _PREFERENCE_KEYS):
                    raise ValueError('existing proxy preference requires explicit migration')
                value = {'ProxyAutoConfigEnable': 1,
                         'ProxyAutoConfigURLString': f'http://127.0.0.1:{self.port}/slipstream-https.pac'}
                if not store.add('State:' + suffix, value):
                    raise ValueError('network service proxy state already owned')
                self.keys['State:' + suffix] = value
            self.store = store
        except BaseException:
            store.close()
            self.keys = {}
            raise

    def close(self):
        with self.lock:
            if self.store is not None:
                self.store.close()
                self.store = None
            self.keys = {}

    def owns_effective_proxy(self):
        with self.lock:
            return self._owns_effective_proxy()

    def _owns_effective_proxy(self):
        if self.store is None:
            return False
        effective = self.store.get('State:/Network/Global/Proxies') or {}
        return (effective.get('ProxyAutoConfigEnable') == 1
                and effective.get('ProxyAutoConfigURLString') == f'http://127.0.0.1:{self.port}/slipstream-https.pac'
                and all(self.store.get(key) == value for key, value in self.keys.items()))

    def needs_refresh(self):
        with self.lock:
            if self.store is None:
                return True
            primary = set()
            for family in ('IPv4', 'IPv6'):
                service = (self.store.get('State:/Network/Global/' + family) or {}).get('PrimaryService')
                if service:
                    primary.add('State:/Network/Service/' + service + '/Proxies')
            if primary != set(self.keys):
                return True
            for key, value in self.keys.items():
                if self.store.get(key) != value:
                    return True
                setup = self.store.get(key.replace('State:', 'Setup:', 1)) or {}
                if any(key in setup for key in _PREFERENCE_KEYS):
                    return True
            return False
