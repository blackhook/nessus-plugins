#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0561 and 
# CentOS Errata and Security Advisory 2008:0561 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43694);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
  script_bugtraq_id(29903, 30036);
  script_xref(name:"RHSA", value:"2008:0561");

  script_name(english:"CentOS 4 / 5 : ruby (CESA-2008:0561)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for quick and easy
object-oriented programming.

Multiple integer overflows leading to a heap overflow were discovered
in the array- and string-handling code used by Ruby. An attacker could
use these flaws to crash a Ruby application or, possibly, execute
arbitrary code with the privileges of the Ruby application using
untrusted inputs in array or string operations. (CVE-2008-2376,
CVE-2008-2662, CVE-2008-2663, CVE-2008-2725, CVE-2008-2726)

It was discovered that Ruby used the alloca() memory allocation
function in the format (%) method of the String class without properly
restricting maximum string length. An attacker could use this flaw to
crash a Ruby application or, possibly, execute arbitrary code with the
privileges of the Ruby application using long, untrusted strings as
format strings. (CVE-2008-2664)

Red Hat would like to thank Drew Yao of the Apple Product Security
team for reporting these issues.

Users of Ruby should upgrade to these updated packages, which contain
a backported patch to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015111.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21d2cfe8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afd701a7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015117.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?56a92005"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015121.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7cd80a0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"irb-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"irb-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-devel-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-devel-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-docs-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-docs-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-libs-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-libs-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-mode-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-mode-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ruby-tcltk-1.8.1-7.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ruby-tcltk-1.8.1-7.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"ruby-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-devel-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-docs-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-irb-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-libs-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-mode-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-rdoc-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-ri-1.8.5-5.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-tcltk-1.8.5-5.el5_2.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-irb / ruby-libs / etc");
}
