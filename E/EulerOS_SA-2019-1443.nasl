#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124946);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2015-8605",
    "CVE-2016-2774",
    "CVE-2017-3144",
    "CVE-2018-5732",
    "CVE-2018-5733"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : dhcp (EulerOS-SA-2019-1443)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the dhcp packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - ISC DHCP 4.x before 4.1-ESV-R12-P1, 4.2.x, and 4.3.x
    before 4.3.3-P1 allows remote attackers to cause a
    denial of service (application crash) via an invalid
    length field in a UDP IPv4 packet.(CVE-2015-8605)

  - A denial of service flaw was found in the way dhcpd
    handled reference counting when processing client
    requests. A malicious DHCP client could use this flaw
    to trigger a reference count overflow on the server
    side, potentially causing dhcpd to crash, by sending
    large amounts of traffic.(CVE-2018-5733)

  - An out-of-bound memory access flaw was found in the way
    dhclient processed a DHCP response packet. A malicious
    DHCP server could potentially use this flaw to crash
    dhclient processes running on DHCP client machines via
    a crafted DHCP response packet.(CVE-2018-5732)

  - A resource-consumption flaw was discovered in the DHCP
    server. dhcpd did not restrict the number of open
    connections to OMAPI and failover ports. A remote
    attacker able to establish TCP connections to one of
    these ports could use this flaw to cause dhcpd to exit
    unexpectedly, stop responding requests, or exhaust
    system sockets (denial of service).(CVE-2016-2774)

  - It was found that the DHCP daemon did not properly
    clean up closed OMAPI connections in certain cases. A
    remote attacker able to connect to the OMAPI port could
    use this flaw to exhaust file descriptors in the DHCP
    daemon, leading to a denial of service in the OMAPI
    functionality.(CVE-2017-3144)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1443
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?478f042c");
  script_set_attribute(attribute:"solution", value:
"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2774");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-5733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-libs");
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

pkgs = ["dhclient-4.2.5-68.1.h10",
        "dhcp-4.2.5-68.1.h10",
        "dhcp-common-4.2.5-68.1.h10",
        "dhcp-libs-4.2.5-68.1.h10"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
