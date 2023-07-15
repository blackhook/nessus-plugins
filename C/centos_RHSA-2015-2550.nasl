#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2550 and 
# CentOS Errata and Security Advisory 2015:2550 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87224);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317", "CVE-2015-8710");
  script_xref(name:"RHSA", value:"2015:2550");

  script_name(english:"CentOS 7 : libxml2 (CESA-2015:2550)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

Several denial of service flaws were found in libxml2, a library
providing support for reading, modifying, and writing XML and HTML
files. A remote attacker could provide a specially crafted XML or HTML
file that, when processed by an application using libxml2, would cause
that application to use an excessive amount of CPU, leak potentially
sensitive information, or in certain cases crash the application.
(CVE-2015-1819, CVE-2015-5312, CVE-2015-7497, CVE-2015-7498,
CVE-2015-7499, CVE-2015-7500 CVE-2015-7941, CVE-2015-7942,
CVE-2015-8241, CVE-2015-8242, CVE-2015-8317, BZ#1213957, BZ#1281955)

Red Hat would like to thank the GNOME project for reporting
CVE-2015-7497, CVE-2015-7498, CVE-2015-7499, CVE-2015-7500,
CVE-2015-8241, CVE-2015-8242, and CVE-2015-8317. Upstream acknowledges
Kostya Serebryany of Google as the original reporter of CVE-2015-7497,
CVE-2015-7498, CVE-2015-7499, and CVE-2015-7500; Hugh Davenport as the
original reporter of CVE-2015-8241 and CVE-2015-8242; and Hanno Boeck
as the original reporter of CVE-2015-8317. The CVE-2015-1819 issue was
discovered by Florian Weimer of Red Hat Product Security.

All libxml2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-December/002730.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29b52cd4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8710");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxml2-2.9.1-6.el7_2.2", el_string:"el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxml2-devel-2.9.1-6.el7_2.2", el_string:"el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxml2-python-2.9.1-6.el7_2.2", el_string:"el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libxml2-static-2.9.1-6.el7_2.2", el_string:"el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python / libxml2-static");
}
