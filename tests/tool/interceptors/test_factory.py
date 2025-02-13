import unittest
from unittest.mock import patch

from safety.tool.interceptors.types import InterceptorType
from safety.tool.interceptors.unix import UnixAliasInterceptor
from safety.tool.interceptors.windows import WindowsInterceptor
from safety.tool.interceptors.factory import create_interceptor


class TestFactory(unittest.TestCase):
    def test_explicit_unix_alias_interceptor(self):
        interceptor = create_interceptor(InterceptorType.UNIX_ALIAS)
        self.assertIsInstance(interceptor, UnixAliasInterceptor)
        
    def test_explicit_windows_interceptor(self):
        interceptor = create_interceptor(InterceptorType.WINDOWS_BAT)
        self.assertIsInstance(interceptor, WindowsInterceptor)

    @patch('safety.tool.interceptors.factory.platform', 'win32')
    def test_auto_select_windows(self):
        interceptor = create_interceptor()
        self.assertIsInstance(interceptor, WindowsInterceptor)

    def test_auto_select_unix_like(self):
        unix_platforms = ['linux', 'linux2', 'darwin']

        for platform in unix_platforms:
            with self.subTest(platform=platform):
                with patch('safety.tool.interceptors.factory.platform', 
                           platform):
                    interceptor = create_interceptor()
                    self.assertIsInstance(interceptor, UnixAliasInterceptor)                

    @patch('safety.tool.interceptors.factory.platform', 'unsupported_os')
    def test_unsupported_platform(self):
        with self.assertRaises(NotImplementedError) as context:
            create_interceptor()
        self.assertIn("Platform 'unsupported_os' is not supported", 
                     str(context.exception))

    def test_invalid_interceptor_type(self):
        invalid_type = "INVALID_TYPE"
        with self.assertRaises(KeyError):
            create_interceptor(invalid_type)
