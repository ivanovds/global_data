# utils related to trading projects: DR, Trader Profile and so on

import datetime
import copy

from st_common_data import settings


def get_intervals_template(session, default_value):
    temp_date = datetime.date.today()  # just for math operations
    start_datetime = datetime.datetime.combine(temp_date, settings.SESSION_TIME_INTERVAL[session][0])
    end_datetime = datetime.datetime.combine(temp_date, settings.SESSION_TIME_INTERVAL[session][1])
    intervals = divmod((end_datetime - start_datetime).total_seconds(), 300)
    intervals = int(intervals[0])

    template = {}
    for interval in range(intervals):
        default_value = copy.deepcopy(default_value)  # in case of default_value is mutable
        template[start_datetime.time()] = default_value
        start_datetime += datetime.timedelta(minutes=5)

    return template


def get_intervals_all_sessions_template(default_value):
    intraday = get_intervals_template(settings.INTRADAY, default_value)
    postmarket = get_intervals_template(settings.POSTMARKET, default_value)
    premarket = get_intervals_template(settings.PREMARKET, default_value)

    template = {}
    template.update(intraday)
    template.update(postmarket)
    template.update(premarket)
    return template


def get_intervals_template_in_regular_timeframe(default_value):
    premarket = get_intervals_template(settings.PREMARKET, default_value)
    intraday = get_intervals_template(settings.INTRADAY, default_value)
    postmarket = get_intervals_template(settings.POSTMARKET, default_value)

    template = {}
    template.update(premarket)
    template.update(intraday)
    template.update(postmarket)
    return template
