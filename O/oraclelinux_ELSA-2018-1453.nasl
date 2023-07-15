#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1453 and 
# Oracle Linux Security Advisory ELSA-2018-1453 respectively.
#

include("compat.inc");

if (description)
{
  script_id(109826);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/27 13:00:38");

  script_cve_id("CVE-2018-1111");
  script_xref(name:"RHSA", value:"2018:1453");
  script_xref(name:"IAVA", value:"2018-A-0162");

  script_name(english:"Oracle Linux 7 : dhcp (ELSA-2018-1453)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2018:1453 :

An update for dhcp is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address. The dhcp packages provide a relay agent and ISC
DHCP service required to enable and administer DHCP on a network.

Security Fix(es) :

* A command injection flaw was found in the NetworkManager integration
script included in the DHCP client packages in Red Hat Enterprise
Linux. A malicious DHCP server, or an attacker on the local network
able to spoof DHCP responses, could use this flaw to execute arbitrary
commands with root privileges on systems using NetworkManager and
configured to obtain network configuration using the DHCP protocol.
(CVE-2018-1111)

Red Hat would like to thank Felix Wilhelm (Google Security Team) for
reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2018-May/007726.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'DHCP Client Command Injection (DynoRoot)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dhclient-4.2.5-68.0.1.el7_5.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dhcp-4.2.5-68.0.1.el7_5.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dhcp-common-4.2.5-68.0.1.el7_5.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dhcp-devel-4.2.5-68.0.1.el7_5.1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dhcp-libs-4.2.5-68.0.1.el7_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-common / dhcp-devel / dhcp-libs");
}
