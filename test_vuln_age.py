from daily_metrics import *
import unittest

class TestVulnAge(unittest.TestCase):
    today = datetime.now(tz=timezone.utc)
    yesterday = today - timedelta(days=1)
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

    def testTodaysDateIsAddedCorrectly(self):
        adv_id = "abcdef"
        two_days_ago = self.today - timedelta(days=2)
        times = [two_days_ago, self.yesterday]
        adv_history = [[adv_id], [adv_id]]

        add_today_to_project_history(times, adv_history)
        age = tally_time_delta(adv_id,adv_history,times)

        assert len(times) == 3
        assert age.days == 2
        assert times[-1].day == self.today.day
        assert times[-1].month == self.today.month
        assert times[-1].year == self.today.year

    def testTodaysDataReplicatesThePreviousReport(self):
        adv_a_id = "abcdef"
        adv_b_id = "zyx"
        adv_c_id = "foo"
        yesterdays_adv = [adv_a_id,adv_b_id,adv_c_id]
        adv_history = [yesterdays_adv]
        times = [self.yesterday]

        add_today_to_project_history(times, adv_history)

        assert len(times) == 2
        assert len(adv_history) == 2
        assert len(adv_history[0]) == len(adv_history[-1])
        assert adv_history[0] == adv_history[-1]

    def testAddingTodaysDummyReportDoesNotAddFalsePositives(self):
        adv_id = "abcdef"
        oldest_adv = [adv_id]
        oldest_date = self.today - timedelta(days=2)
        adv_history = [oldest_adv, []]
        times = [oldest_date,self.yesterday]

        add_today_to_project_history(times, adv_history)
        age = tally_time_delta(adv_id,adv_history,times)

        assert age.days == 0
