from daily_metrics import *
import unittest

class TestVulnAge(unittest.TestCase):
    def testShouldCorrectlyCalculateAge(self):
        times = [datetime(day=1, month=1, year=1), datetime(day=3, month=1, year=1)]
        adv_history = [["abcdef"], ["abcdef"]]
        adv_id = "abcdef"

        td = tally_time_delta(adv_id,adv_history,times)

        assert td.days == 2

    def testAgeStopsOnceMitigated(self):
        times = [datetime(day=1, month=1, year=1), datetime(day=3, month=1, year=1), datetime(day=4, month=1, year=1)]
        adv_history = [["abcdef"], ["abcdef"], []]
        adv_history_1 = [["abcdef"], ["abcdef"], [], []]
        times_1 = [datetime(day=1, month=1, year=1), datetime(day=3, month=1, year=1), datetime(day=4, month=1, year=1), datetime(day=5,month=1,year=1)]
        adv_id = "abcdef"

        td = tally_time_delta(adv_id, adv_history, times)
        td_1 = tally_time_delta(adv_id,adv_history_1,times_1)

        assert td.days == 0
        assert td_1.days == 0

    def testAgeShouldBeResetIfVulnReintroduced(self):
        times = [datetime(day=1, month=1, year=1), datetime(day=3, month=1, year=1), datetime(day=4, month=1, year=1),datetime(day=6,month=1,year=1)]
        adv_history = [["abcdef"], [], ["abcdef"],["abcdef"]]
        adv_id = "abcdef"

        td = tally_time_delta(adv_id, adv_history, times)

        assert td.days == 2, "age should reset once vulnerability is mitigated, if it reappears a new count starts"

    def testCorrectAgeIfNew(self):
        times = [datetime(day=1, month=1, year=1), datetime(day=3, month=1, year=1), datetime(day=4, month=1, year=1)]
        adv_history = [[], [], ["abcdef"]]
        adv_id = "abcdef"

        td = tally_time_delta(adv_id, adv_history, times)

        assert td.days == 0

    def testCorrectAgeIfIntroducedPartWay(self):
        times = [datetime(day=1, month=1, year=1), datetime(day=3, month=1, year=1), datetime(day=5, month=1, year=1), datetime(day=8,month=1,year=1), datetime(day=9,month=1,year=1)]
        adv_history = [[], [],  ["abcdef"], ["abcdef"],["abcdef"]]
        adv_id = "abcdef"

        td = tally_time_delta(adv_id, adv_history, times)

        assert td.days == 4

