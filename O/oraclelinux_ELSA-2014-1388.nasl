#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1388 and 
# Oracle Linux Security Advisory ELSA-2014-1388 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78522);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-2856", "CVE-2014-3537", "CVE-2014-5029", "CVE-2014-5030", "CVE-2014-5031");
  script_bugtraq_id(66788, 68788, 68842, 68846, 68847);
  script_xref(name:"RHSA", value:"2014:1388");

  script_name(english:"Oracle Linux 6 : cups (ELSA-2014-1388)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1388 :

Updated cups packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

CUPS provides a portable printing layer for Linux, UNIX, and similar
operating systems.

A cross-site scripting (XSS) flaw was found in the CUPS web interface.
An attacker could use this flaw to perform a cross-site scripting
attack against users of the CUPS web interface. (CVE-2014-2856)

It was discovered that CUPS allowed certain users to create symbolic
links in certain directories under /var/cache/cups/. A local user with
the 'lp' group privileges could use this flaw to read the contents of
arbitrary files on the system or, potentially, escalate their
privileges on the system. (CVE-2014-3537, CVE-2014-5029,
CVE-2014-5030, CVE-2014-5031)

The CVE-2014-3537 issue was discovered by Francisco Alonso of Red Hat
Product Security.

These updated cups packages also include several bug fixes. Space
precludes documenting all of these changes in this advisory. Users are
directed to the Red Hat Enterprise Linux 6.6 Technical Notes, linked
to in the References section, for information on the most significant
of these changes.

All cups users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, the cupsd daemon will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-October/004527.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cups-php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL6", reference:"cups-1.4.2-67.el6")) flag++;
if (rpm_check(release:"EL6", reference:"cups-devel-1.4.2-67.el6")) flag++;
if (rpm_check(release:"EL6", reference:"cups-libs-1.4.2-67.el6")) flag++;
if (rpm_check(release:"EL6", reference:"cups-lpd-1.4.2-67.el6")) flag++;
if (rpm_check(release:"EL6", reference:"cups-php-1.4.2-67.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs / cups-lpd / cups-php");
}
