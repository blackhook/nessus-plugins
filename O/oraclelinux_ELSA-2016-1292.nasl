#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1292 and 
# Oracle Linux Security Advisory ELSA-2016-1292 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91797);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4448", "CVE-2016-4449");
  script_xref(name:"RHSA", value:"2016:1292");

  script_name(english:"Oracle Linux 6 / 7 : libxml2 (ELSA-2016-1292)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1292 :

An update for libxml2 is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

[Updated 18 July 2016] This advisory has been updated to push packages
into the Red Hat Enterprise Linux 6 Desktop channels. The packages
included in this revised update have not been changed in any way from
the packages included in the original advisory.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

Security Fix(es) :

A heap-based buffer overflow flaw was found in the way libxml2 parsed
certain crafted XML input. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash or execute arbitrary
code with the permissions of the user running the application.
(CVE-2016-1834, CVE-2016-1840)

Multiple denial of service flaws were found in libxml2. A remote
attacker could provide a specially crafted XML file that, when
processed by an application using libxml2, could cause that
application to crash. (CVE-2016-1762, CVE-2016-1833, CVE-2016-1835,
CVE-2016-1836, CVE-2016-1837, CVE-2016-1838, CVE-2016-1839,
CVE-2016-3627, CVE-2016-3705, CVE-2016-4447, CVE-2016-4448,
CVE-2016-4449)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-June/006135.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-June/006139.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4448");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"libxml2-2.7.6-21.0.1.el6_8.1", el_string:"el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-devel-2.7.6-21.0.1.el6_8.1", el_string:"el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-python-2.7.6-21.0.1.el6_8.1", el_string:"el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"libxml2-static-2.7.6-21.0.1.el6_8.1", el_string:"el6_8")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libxml2-2.9.1-6.0.1.el7_2.3", el_string:"el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libxml2-devel-2.9.1-6.0.1.el7_2.3", el_string:"el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libxml2-python-2.9.1-6.0.1.el7_2.3", el_string:"el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libxml2-static-2.9.1-6.0.1.el7_2.3", el_string:"el7_2")) flag++;


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
