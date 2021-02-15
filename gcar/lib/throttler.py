import logging
import datetime

logger = logging.getLogger(__name__)

class Throttler:
    def __init__(self, throttle_delta):
        """
        Args:
            throttle_delta (datetime.timedelta): throttle delta in weeks/days/hours/minutes/seconds/milliseconds/microseconds
        """
        self.throttle_delta = throttle_delta

    def update(self, id):
        self._set(id, datetime.datetime.now())

    def is_throttled(self, id):
        last_time = self._get(id)
        if last_time is None:
            return False

        return (datetime.datetime.now() - last_time) < self.throttle_delta

    def _set(self, id, time):
        raise NotImplementedError

    def _get(self, id):
        raise NotImplementedError


class TimeThrottler(Throttler):
    def __init__(self, *args, **kwargs):
        super(TimeThrottler, self).__init__(*args, **kwargs)
        self._datetimes = {}

    def _set(self, id, time):
        self._datetimes[id] = time

    def _get(self, id):
        return self._datetimes.get(id)