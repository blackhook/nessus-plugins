#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2549 and 
# Oracle Linux Security Advisory ELSA-2015-2549 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87230);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_xref(name:"RHSA", value:"2015:2549");

  script_name(english:"Oracle Linux 6 : libxml2 (ELSA-2015-2549)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2549 :

Updated libxml2 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

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
(CVE-2015-5312, CVE-2015-7497, CVE-2015-7498, CVE-2015-7499,
CVE-2015-7500 CVE-2015-7941, CVE-2015-7942, CVE-2015-8241,
CVE-2015-8242, CVE-2015-8317, BZ#1213957, BZ#1281955)

Red Hat would like to thank the GNOME project for reporting
CVE-2015-7497, CVE-2015-7498, CVE-2015-7499, CVE-2015-7500,
CVE-2015-8241, CVE-2015-8242, and CVE-2015-8317. Upstream acknowledges
Kostya Serebryany of Google as the original reporter of CVE-2015-7497,
CVE-2015-7498, CVE-2015-7499, and CVE-2015-7500; Hugh Davenport as the
original reporter of CVE-2015-8241 and CVE-2015-8242; and Hanno Boeck
as the original reporter of CVE-2015-8317.

All libxml2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-December/005601.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"libxml2-2.7.6-20.0.1.el6_7.1")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-devel-2.7.6-20.0.1.el6_7.1")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-python-2.7.6-20.0.1.el6_7.1")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-static-2.7.6-20.0.1.el6_7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2 / libxml2-devel / libxml2-python / libxml2-static");
}
