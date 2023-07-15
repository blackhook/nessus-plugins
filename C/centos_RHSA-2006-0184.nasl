#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0184 and 
# CentOS Errata and Security Advisory 2006:0184 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21981);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0019");
  script_xref(name:"RHSA", value:"2006:0184");

  script_name(english:"CentOS 4 : kdelibs (CESA-2006:0184)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages are now available for Red Hat Enterprise
Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

kdelibs contains libraries for the K Desktop Environment (KDE).

A heap overflow flaw was discovered affecting kjs, the JavaScript
interpreter engine used by Konqueror and other parts of KDE. An
attacker could create a malicious website containing carefully crafted
JavaScript code that would trigger this flaw and possibly lead to
arbitrary code execution. The Common Vulnerabilities and Exposures
project assigned the name CVE-2006-0019 to this issue.

NOTE: this issue does not affect KDE in Red Hat Enterprise Linux 3 or
2.1.

Users of KDE should upgrade to these updated packages, which contain a
backported patch from the KDE security team correcting this issue as
well as two bug fixes."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012587.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?adddae31"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012588.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab0cb0be"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbb4c0dd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"kdelibs-3.3.1-3.14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdelibs-devel-3.3.1-3.14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-devel");
}
