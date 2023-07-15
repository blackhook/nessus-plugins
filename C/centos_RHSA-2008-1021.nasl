#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:1021 and 
# CentOS Errata and Security Advisory 2008:1021 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35172);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-3863", "CVE-2008-4306", "CVE-2008-5078");
  script_xref(name:"RHSA", value:"2008:1021");

  script_name(english:"CentOS 3 / 4 : enscript (CESA-2008:1021)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated enscript packages that fixes several security issues is now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GNU enscript converts ASCII files to PostScript(R) language files and
spools the generated output to a specified printer or saves it to a
file. Enscript can be extended to handle different output media and
includes options for customizing printouts.

Several buffer overflow flaws were found in GNU enscript. An attacker
could craft an ASCII file in such a way that it could execute
arbitrary commands if the file was opened with enscript with the
'special escapes' option (-e or --escapes) enabled. (CVE-2008-3863,
CVE-2008-4306, CVE-2008-5078)

All users of enscript should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?755cbf63"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e89c0d55"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015482.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2edc9876"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7d0b119"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015510.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17f65482"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-December/015511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3caa88b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected enscript package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:enscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"enscript-1.6.1-24.7")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"enscript-1.6.1-33.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"enscript-1.6.1-33.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"enscript-1.6.1-33.el4_7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "enscript");
}
