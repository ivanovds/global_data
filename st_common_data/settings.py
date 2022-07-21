import datetime


INTRADAY = 'INT'
POSTMARKET = 'POS'
PREMARKET = 'PRE'

SESSION_TIME_INTERVAL = {
    INTRADAY: [datetime.time(10, 0, 0), datetime.time(16, 0, 0)],
    POSTMARKET: [datetime.time(16, 0, 0), datetime.time(20, 0, 0)],
    PREMARKET: [datetime.time(4, 0, 0), datetime.time(10, 0, 0)],
}

OFFICIAL_SESSION_TIME_INTERVAL = {
    INTRADAY: [datetime.time(9, 30, 0), datetime.time(16, 0, 0)],
    POSTMARKET: [datetime.time(16, 0, 0), datetime.time(20, 0, 0)],
    PREMARKET: [datetime.time(4, 0, 0), datetime.time(9, 30, 0)],
}
