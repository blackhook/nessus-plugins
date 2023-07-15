#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125010);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-9296",
    "CVE-2015-1798",
    "CVE-2015-7705",
    "CVE-2015-7850",
    "CVE-2015-7853",
    "CVE-2015-7855",
    "CVE-2015-7871",
    "CVE-2015-7976",
    "CVE-2018-7185"
  );
  script_bugtraq_id(
    71758,
    73951
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : ntp (EulerOS-SA-2019-1557)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ntp packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - It was found that ntpd did not check whether a Message
    Authentication Code (MAC) was present in a received
    packet when ntpd was configured to use symmetric
    cryptographic keys. A man-in-the-middle attacker could
    use this flaw to send crafted packets that would be
    accepted by a client or a peer without the attacker
    knowing the symmetric key.(CVE-2015-1798)

  - A missing return statement in the receive() function
    could potentially allow a remote attacker to bypass
    NTP's authentication mechanism.(CVE-2014-9296)

  - The rate limiting feature in NTP 4.x before 4.2.8p4 and
    4.3.x before 4.3.77 allows remote attackers to have
    unspecified impact via a large number of crafted
    requests.(CVE-2015-7705)

  - The datalen parameter in the refclock driver in NTP
    4.2.x before 4.2.8p4, and 4.3.x before 4.3.77 allows
    remote attackers to execute arbitrary code or cause a
    denial of service (crash) via a negative input
    value.(CVE-2015-7853)

  - Crypto-NAK packets in ntpd in NTP 4.2.x before 4.2.8p4,
    and 4.3.x before 4.3.77 allows remote attackers to
    bypass authentication.(CVE-2015-7871)

  - The protocol engine in ntp 4.2.6 before 4.2.8p11 allows
    a remote attackers to cause a denial of service
    (disruption) by continually sending a packet with a
    zero-origin timestamp and source IP address of the
    ''other side'' of an interleaved association causing
    the victim ntpd to reset its
    association.(CVE-2018-7185)

  - The ntpq saveconfig command in NTP 4.1.2, 4.2.x before
    4.2.8p6, 4.3, 4.3.25, 4.3.70, and 4.3.77 does not
    properly filter special characters, which allows
    attackers to cause unspecified impact via a crafted
    filename.(CVE-2015-7976)

  - ntpd in NTP 4.2.x before 4.2.8p4, and 4.3.x before
    4.3.77 allows remote authenticated users to cause a
    denial of service (infinite loop or crash) by pointing
    the key file at the log file.(CVE-2015-7850)

  - The decodenetnum function in ntpd in NTP 4.2.x before
    4.2.8p4, and 4.3.x before 4.3.77 allows remote
    attackers to cause a denial of service (assertion
    failure) via a 6 or mode 7 packet containing a long
    data value.(CVE-2015-7855)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1557
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?976b810f");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
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

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
