#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2590 and 
# CentOS Errata and Security Advisory 2016:2590 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95336);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-2774");
  script_xref(name:"RHSA", value:"2016:2590");

  script_name(english:"CentOS 7 : dhcp (CESA-2016:2590)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for dhcp is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Dynamic Host Configuration Protocol (DHCP) is a protocol that
allows individual devices on an IP network to get their own network
configuration information, including an IP address, a subnet mask, and
a broadcast address. The dhcp packages provide a relay agent and ISC
DHCP service required to enable and administer DHCP on a network.

Security Fix(es) :

* A resource-consumption flaw was discovered in the DHCP server. dhcpd
did not restrict the number of open connections to OMAPI and failover
ports. A remote attacker able to establish TCP connections to one of
these ports could use this flaw to cause dhcpd to exit unexpectedly,
stop responding requests, or exhaust system sockets (denial of
service). (CVE-2016-2774)

Red Hat would like to thank ISC for reporting this issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003584.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dffb2a89"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2774");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dhclient-4.2.5-47.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dhcp-4.2.5-47.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dhcp-common-4.2.5-47.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dhcp-devel-4.2.5-47.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dhcp-libs-4.2.5-47.el7.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhclient / dhcp / dhcp-common / dhcp-devel / dhcp-libs");
}
