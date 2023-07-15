#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1160 and 
# CentOS Errata and Security Advisory 2011:1160 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55860);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2748", "CVE-2011-2749");
  script_bugtraq_id(49120);
  script_xref(name:"RHSA", value:"2011:1160");

  script_name(english:"CentOS 4 / 5 : dhcp (CESA-2011:1160)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dhcp packages that fix two security issues are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address.

Two denial of service flaws were found in the way the dhcpd daemon
handled certain incomplete request packets. A remote attacker could
use these flaws to crash dhcpd via a specially crafted request.
(CVE-2011-2748, CVE-2011-2749)

Users of DHCP should upgrade to these updated packages, which contain
a backported patch to correct these issues. After installing this
update, all DHCP servers will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017692.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5db5bd8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-August/017693.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d0237a7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017800.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?078a158d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017851.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f43a3579"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000202.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c361fa86"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000203.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a583959b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdhcp4client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libdhcp4client-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhclient-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhclient-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhcp-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhcp-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"dhcp-devel-3.0.1-68.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"dhcp-devel-3.0.1-68.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"dhclient-3.0.5-29.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dhcp-3.0.5-29.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dhcp-devel-3.0.5-29.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libdhcp4client-3.0.5-29.el5_7.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libdhcp4client-devel-3.0.5-29.el5_7.1")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-devel / libdhcp4client / etc");
}
