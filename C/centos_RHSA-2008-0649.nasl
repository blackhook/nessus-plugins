#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0649 and 
# CentOS Errata and Security Advisory 2008:0649 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43704);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-2935");
  script_bugtraq_id(30467);
  script_xref(name:"RHSA", value:"2008:0649");

  script_name(english:"CentOS 4 / 5 : libxslt (CESA-2008:0649)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxslt packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

libxslt is a library for transforming XML files into other XML files
using the standard XSLT stylesheet transformation mechanism.

A heap buffer overflow flaw was discovered in the RC4 libxslt library
extension. An attacker could create a malicious XSL file that would
cause a crash, or, possibly, execute arbitrary code with the
privileges of the application using the libxslt library to perform XSL
transformations on untrusted XSL style sheets. (CVE-2008-2935)

Red Hat would like to thank Chris Evans for reporting this
vulnerability.

All libxslt users are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015176.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac975a3d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015177.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a45cdd1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-July/015178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a1f7086"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxslt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxslt-1.1.11-1.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxslt-devel-1.1.11-1.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxslt-python-1.1.11-1.c4.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libxslt-1.1.17-2.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxslt-devel-1.1.17-2.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxslt-python-1.1.17-2.el5_2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt / libxslt-devel / libxslt-python");
}
