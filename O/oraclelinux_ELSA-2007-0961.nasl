#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0961 and 
# Oracle Linux Security Advisory ELSA-2007-0961 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67584);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-6303", "CVE-2007-5162", "CVE-2007-5770");
  script_bugtraq_id(25847, 26421);
  script_xref(name:"RHSA", value:"2007:0961");

  script_name(english:"Oracle Linux 4 : ruby (ELSA-2007-0961)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0961 :

Updated ruby packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for object-oriented
programming.

A flaw was discovered in the way Ruby's CGI module handles certain
HTTP requests. If a remote attacker sends a specially crafted request,
it is possible to cause the ruby CGI script to enter an infinite loop,
possibly causing a denial of service. (CVE-2006-6303)

An SSL certificate validation flaw was discovered in several Ruby Net
modules. The libraries were not checking the requested host name
against the common name (CN) in the SSL server certificate, possibly
allowing a man in the middle attack. (CVE-2007-5162, CVE-2007-5770)

Users of Ruby should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-November/000395.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"irb-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"irb-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-devel-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-devel-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-docs-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-docs-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-libs-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-libs-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-mode-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-mode-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-tcltk-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-tcltk-1.8.1-7.EL4.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-libs / ruby-mode / etc");
}
