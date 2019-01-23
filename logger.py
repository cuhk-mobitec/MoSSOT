import logging
import colorlog


class MyLogger(object):
    def __init__(self, name='Init', level='DEBUG'):
        # add custom level "VERBOSE"
        VERBOSE = 5
        logging.addLevelName(VERBOSE, "VERBOSE")
        logging.Logger.verbose = lambda inst, msg, *args, **kwargs: inst.log(VERBOSE, msg, *args, **kwargs)

        # color and format
        formatter = colorlog.ColoredFormatter(
            '[%(name)s][%(levelname)s]%(asctime)s %(log_color)s%(message)s',
            datefmt='%m-%d %H:%M')

        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(formatter)
        _logger = logging.getLogger(name)
        _logger.setLevel(logging.DEBUG)
        _logger.addHandler(handler)
        self.logger = _logger

    def get_logger(self):
        return self.logger

