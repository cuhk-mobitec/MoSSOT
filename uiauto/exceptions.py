class AppNotRunningException(Exception):
    """Raise when app accidentally exited"""


class SkipIrrelevantExceedLimit(Exception):
    """Reach maximum recursive call of skip_irrelevant"""


class GenymotionTimeoutException(Exception):
    """Genymotion management action timeout"""


class GenymotionActionException(Exception):
    """Genymotion management action exception"""


class GenymotionInitException(Exception):
    """Genymotion initialization exception"""


class PathJsonBuilderException(Exception):
    """Exception when building path JSON"""
