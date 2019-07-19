"""
Exceptions
"""


class TestInitException(Exception):
    """Raise when test fail to initialize"""


class AppNotRunningException(Exception):
    """Raise when app accidentally exited"""


class SkipIrrelevantExceedLimit(Exception):
    """Reach maximum recursive call of skip_irrelevant"""


class EmulatorInitException(Exception):
    """Emulator initialization exception"""


class EmulatorTimeoutException(Exception):
    """Emulator management action timeout"""


class EmulatorActionException(Exception):
    """Emulator management action exception"""


class ADBActionException(Exception):
    """Emulator ADB management action exception"""


class PathJsonBuilderException(Exception):
    """Exception when building path JSON"""


class PathNotDefinedInConfig(Exception):
    """Cannot find a specific path key in JSON config"""


class NoSafeClickableElement(Exception):
    """There's no safe clickable element, might require update"""


class ManifestParsingException(Exception):
    """Error occured while parsing APK manifest file"""


class IdPHandlingException(Exception):
    """Error occured while handling idp login process"""
