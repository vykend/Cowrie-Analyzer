import json
import operator
import glob
import os
import matplotlib.pyplot as plt
from dateutil.parser import parse
from datetime import timedelta
from collections import defaultdict


def bin_by_hours(given_time, bin_amt):
    return given_time - timedelta(hours=given_time.hour % bin_amt, minutes=given_time.minute,
                                  seconds=given_time.second, microseconds=given_time.microsecond)


# does a quick analysis of cowrie json logs, and prints some details to stdout
# currently prints the total number of ssh attempts
# top 30 IPs that attempt logins
# top 30 username attempts
# top 30 password attempts
# top 30 username:password combo attempts
# top 30 countries by total number of source IPs
# top 30 countries by total number of attacks
# in directory 'outs' are saved times for top 30 source IPs for further (time-based) analysis
class CowrieAnalyzer:
    def __init__(self, json_dir='cowrie'):
        self.files = glob.glob(json_dir + os.sep + 'cowrie.jso*')
        self.num_ssh = 0
        self.src_ip_cnt = defaultdict(int)  # defaultdict, so no special case for the first instance of a count
        self.username_cnt = defaultdict(int)
        self.pass_cnt = defaultdict(int)
        self.userpass_cnt = defaultdict(int)
        self.ssh_times_cnt = defaultdict(int)
        self.geoip_lookup = defaultdict(int)
        self.ip_time = []

    def plot(self):
        fig = plt.figure()
        ax = fig.add_subplot(111)
        ax.set_xlabel('Time')
        ax.set_ylabel('Attack Attempts')
        ax.set_title('Attack Attempts per Day - groups by hour')
        dates, ssh_attempts = zip(*sorted(self.ssh_times_cnt.items()))
        ax.plot(dates, ssh_attempts, 'b-', label='SSH Attempts')
        ax.legend()
        fig.autofmt_xdate()
        # plt.show()
        fig.savefig('attack_attempts.png', dpi=600)

    def run(self):
        total_contents = []
        for file in self.files:
            with open(file) as openfile:
                for line in openfile:
                    total_contents.append(json.loads(line))

        num_ssh = 0
        for event in total_contents:
            if 'cowrie.session.connect' in event['eventid']:
                if 'ssh' in event['protocol']:
                    num_ssh += 1
                    time = bin_by_hours(parse(event['timestamp']), 1)
                    self.ssh_times_cnt[time] += 1

            if 'cowrie.login' in event['eventid']:
                self.src_ip_cnt[event['src_ip']] += 1
                self.username_cnt[event['username']] += 1
                self.pass_cnt[event['password']] += 1
                self.userpass_cnt[event['username'] + ':' + event['password']] += 1
                #self.ip_time.append(event['src_ip'] + ', ' + parse(event['timestamp']).strftime("%Y-%m-%d %H:%M:%S"))
                self.ip_time.append([event['src_ip'], event['timestamp']])

        print('SSH attempts:' + str(num_ssh))
        print('most common source addresses:')
        for addr in sorted(self.src_ip_cnt.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            print(addr)
        print('most common username attempts:')
        for user in sorted(self.username_cnt.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            print(user)
        print('most common password attempts:')
        for passw in sorted(self.pass_cnt.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            print(passw)
        print('most common username/password combos:')
        for creds in sorted(self.userpass_cnt.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            print(creds)

        self.plot()
        if os.path.isfile('GeoLite2-Country.mmdb'):
            self.map_ips()
        
        for addr in sorted(self.src_ip_cnt.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            with open("outs/output-" + addr[0] + ".csv", "w") as outfile:
                outfile.write('IP - ' + addr[0] + ', Times - ' + addr[0] + '\n')
                for iptime in self.ip_time:
                    if addr[0] in iptime[0]:
                        outfile.write(iptime[1] + ', 1\n')

    def map_ips(self):
        geoip_overall = defaultdict(int)
        import geoip2.database
        reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
        for addr in sorted(self.src_ip_cnt.items(), key=operator.itemgetter(1), reverse=True):
            response = reader.country(addr[0])
            self.geoip_lookup[response.country.name] += 1  # or += addr[1]
            geoip_overall[response.country.name] += addr[1]
        print('unique source IPs:')
        print(len(self.src_ip_cnt))
        print('unique countries for source IPs:')
        print(len(self.geoip_lookup))
        print('most common countries for source IPs:')
        for country in sorted(self.geoip_lookup.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            print(country)
        print('unique countries for overall attacks:')
        print(len(geoip_overall))
        print('most common countries for overall attacks:')
        for country in sorted(geoip_overall.items(), key=operator.itemgetter(1), reverse=True)[:30]:
            print(country)


# run from the command line
if __name__ == '__main__':
    CowrieAnalyzer().run()
