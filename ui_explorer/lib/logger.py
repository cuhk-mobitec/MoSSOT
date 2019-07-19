import colorlog, logging


class MyLogger(object):
    def __init__(self, name='UIAuto', level='DEBUG'):
        # add custom level "VERBOSE"
        VERBOSE = 5
        logging.addLevelName(VERBOSE, "VERBOSE")
        logging.Logger.verbose = lambda inst, msg, *args, **kwargs: inst.log(VERBOSE, msg, *args, **kwargs)

        # color and format
        formatter = colorlog.ColoredFormatter(
            '[%(name)s][%(levelname)s] %(log_color)s%(message)s')

        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        _logger = logging.getLogger(name)
        _logger.setLevel(level)
        _logger.addHandler(handler)
        self.logger = _logger

    def get_logger(self):
        return self.logger


logger = MyLogger().get_logger()
