#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125008);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2014-9293",
    "CVE-2014-9295",
    "CVE-2015-1799",
    "CVE-2015-5194",
    "CVE-2015-5219",
    "CVE-2015-7692",
    "CVE-2015-7702",
    "CVE-2015-7704",
    "CVE-2015-7977",
    "CVE-2015-8138",
    "CVE-2015-8139",
    "CVE-2015-8158",
    "CVE-2016-1547",
    "CVE-2016-1548",
    "CVE-2016-1550",
    "CVE-2016-4954",
    "CVE-2016-7426",
    "CVE-2016-9310",
    "CVE-2017-6462",
    "CVE-2017-6464"
  );
  script_bugtraq_id(71757, 71761, 73950);

  script_name(english:"EulerOS Virtualization 3.0.1.0 : ntp (EulerOS-SA-2019-1555)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ntp packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - It was found that when ntp is configured with rate
    limiting for all associations the limits are also
    applied to responses received from its configured
    sources. A remote attacker who knows the sources can
    cause a denial of service by preventing ntpd from
    accepting valid responses from its
    sources.(CVE-2016-7426)

  - ntpq in NTP before 4.2.8p7 allows remote attackers to
    obtain origin timestamps and then impersonate peers via
    unspecified vectors.(CVE-2015-8139)

  - A NULL pointer dereference flaw was found in the way
    ntpd processed 'ntpdc reslist' commands that queried
    restriction lists with a large amount of entries. A
    remote attacker could potentially use this flaw to
    crash ntpd.(CVE-2015-7977)

  - A vulnerability was found in NTP, in the parsing of
    packets from the /dev/datum device. A malicious device
    could send crafted messages, causing ntpd to
    crash.(CVE-2017-6462)

  - The process_packet function in ntp_proto.c in ntpd in
    NTP 4.x before 4.2.8p8 allows remote attackers to cause
    a denial of service (peer-variable modification) by
    sending spoofed packets from many source IP addresses
    in a certain scenario, as demonstrated by triggering an
    incorrect leap indication.(CVE-2016-4954)

  - It was found that ntpd could crash due to an
    uninitialized variable when processing malformed
    logconfig configuration commands.(CVE-2015-5194)

  - It was discovered that the sntp utility could become
    unresponsive due to being caught in an infinite loop
    when processing a crafted NTP packet.(CVE-2015-5219)

  - It was discovered that ntpd as a client did not
    correctly check the originate timestamp in received
    packets. A remote attacker could use this flaw to send
    a crafted packet to an ntpd client that would
    effectively disable synchronization with the server, or
    push arbitrary offset/delay measurements to modify the
    time on the client.(CVE-2015-8138)

  - It was found that the fix for CVE-2014-9750 was
    incomplete: three issues were found in the value length
    checks in NTP's ntp_crypto.c, where a packet with
    particular autokey operations that contained malicious
    data was not always being completely validated. A
    remote attacker could use a specially crafted NTP
    packet to crash ntpd.(CVE-2015-7702)

  - Multiple buffer overflow flaws were discovered in
    ntpd's crypto_recv(), ctl_putdata(), and configure()
    functions. A remote attacker could use either of these
    flaws to send a specially crafted request packet that
    could crash ntpd or, potentially, execute arbitrary
    code with the privileges of the ntp user. Note: the
    crypto_recv() flaw requires non default configurations
    to be active, while the ctl_putdata() flaw, by default,
    can only be exploited via local attackers, and the
    configure() flaw requires additional authentication to
    exploit.(CVE-2014-9295)

  - It was found that an ntpd client could be forced to
    change from basic client/server mode to the interleaved
    symmetric mode. A remote attacker could use a spoofed
    packet that, when processed by an ntpd client, would
    cause that client to reject all future legitimate
    server responses, effectively disabling time
    synchronization on that client.(CVE-2016-1548)

  - A flaw was found in the way NTP's libntp performed
    message authentication. An attacker able to observe the
    timing of the comparison function used in packet
    authentication could potentially use this flaw to
    recover the message digest.(CVE-2016-1550)

  - A denial of service flaw was found in the way NTP
    handled preemptable client associations. A remote
    attacker could send several crypto NAK packets to a
    victim client, each with a spoofed source address of an
    existing associated peer, preventing that client from
    synchronizing its time.(CVE-2016-1547)

  - It was found that the fix for CVE-2014-9750 was
    incomplete: three issues were found in the value length
    checks in NTP's ntp_crypto.c, where a packet with
    particular autokey operations that contained malicious
    data was not always being completely validated. A
    remote attacker could use a specially crafted NTP
    packet to crash ntpd.(CVE-2015-7692)

  - A flaw was found in the way the ntpq client processed
    certain incoming packets in a loop in the getresponse()
    function. A remote attacker could potentially use this
    flaw to crash an ntpq client instance.(CVE-2015-8158)

  - It was discovered that ntpd as a client did not
    correctly check timestamps in Kiss-of-Death packets. A
    remote attacker could use this flaw to send a crafted
    Kiss-of-Death packet to an ntpd client that would
    increase the client's polling interval value, and
    effectively disable synchronization with the
    server.(CVE-2015-7704)

  - A flaw was found in the control mode functionality of
    ntpd. A remote attacker could send a crafted control
    mode packet which could lead to information disclosure
    or result in DDoS amplification attacks.(CVE-2016-9310)

  - A vulnerability was discovered in the NTP server's
    parsing of configuration directives. A remote,
    authenticated attacker could cause ntpd to crash by
    sending a crafted message.(CVE-2017-6464)

  - It was found that ntpd automatically generated weak
    keys for its internal use if no ntpdc request
    authentication key was specified in the ntp.conf
    configuration file. A remote attacker able to match the
    configured IP restrictions could guess the generated
    key, and possibly use it to send ntpdc query or
    configuration requests.(CVE-2014-9293)

  - A denial of service flaw was found in the way NTP hosts
    that were peering with each other authenticated
    themselves before updating their internal state
    variables. An attacker could send packets to one peer
    host, which could cascade to other peers, and stop the
    synchronization process among the reached
    peers.(CVE-2015-1799)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1555
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd9b4cf1");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9295");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-6462");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:sntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ntp-4.2.6p5-28.h8",
        "ntpdate-4.2.6p5-28.h8",
        "sntp-4.2.6p5-28.h8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
