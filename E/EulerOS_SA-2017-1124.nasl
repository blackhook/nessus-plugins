#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101310);
  script_version("3.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-8139",
    "CVE-2016-2516",
    "CVE-2016-4954",
    "CVE-2016-4955",
    "CVE-2016-4956",
    "CVE-2017-6462",
    "CVE-2017-6463",
    "CVE-2017-6464"
  );

  script_name(english:"EulerOS 2.0 SP1 : ntp (EulerOS-SA-2017-1124)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ntp packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - ntpq in NTP before 4.2.8p7 allows remote attackers to
    obtain origin timestamps and then impersonate peers via
    unspecified vectors.i1/4^CVE-2015-8139i1/4%0

  - NTP before 4.2.8p7 and 4.3.x before 4.3.92, when mode7
    is enabled, allows remote attackers to cause a denial
    of service (ntpd abort) by using the same IP address
    multiple times in an unconfig
    directive.i1/4^CVE-2016-2516i1/4%0

  - The process_packet function in ntp_proto.c in ntpd in
    NTP 4.x before 4.2.8p8 allows remote attackers to cause
    a denial of service (peer-variable modification) by
    sending spoofed packets from many source IP addresses
    in a certain scenario, as demonstrated by triggering an
    incorrect leap indication.i1/4^CVE-2016-4954i1/4%0

  - ntpd in NTP 4.x before 4.2.8p8, when autokey is
    enabled, allows remote attackers to cause a denial of
    service (peer-variable clearing and association outage)
    by sending (1) a spoofed crypto-NAK packet or (2) a
    packet with an incorrect MAC value at a certain
    time.i1/4^CVE-2016-4955i1/4%0

  - ntpd in NTP 4.x before 4.2.8p8 allows remote attackers
    to cause a denial of service (interleaved-mode
    transition and time change) via a spoofed broadcast
    packet. NOTE: this vulnerability exists because of an
    incomplete fix for CVE-2016-1548.i1/4^CVE-2016-4956i1/4%0

  - Buffer overflow in the legacy Datum Programmable Time
    Server (DPTS) refclock driver in NTP before 4.2.8p10
    and 4.3.x before 4.3.94 allows local users to have
    unspecified impact via a crafted /dev/datum
    device.i1/4^CVE-2017-6462i1/4%0

  - NTP before 4.2.8p10 and 4.3.x before 4.3.94 allows
    remote authenticated users to cause a denial of service
    (daemon crash) via an invalid setting in a :config
    directive, related to the unpeer
    option.i1/4^CVE-2017-6463i1/4%0

  - NTP before 4.2.8p10 and 4.3.x before 4.3.94 allows
    remote attackers to cause a denial of service (ntpd
    crash) via a malformed mode configuration
    directive.i1/4^CVE-2017-6464i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7606168d");
  script_set_attribute(attribute:"solution", value:
"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ntpdate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ntp-4.2.6p5-25.0.1.h13",
        "ntpdate-4.2.6p5-25.0.1.h13"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
