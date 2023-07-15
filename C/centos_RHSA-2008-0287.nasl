#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0287 and 
# CentOS Errata and Security Advisory 2008:0287 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32401);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1767");
  script_bugtraq_id(29312);
  script_xref(name:"RHSA", value:"2008:0287");

  script_name(english:"CentOS 3 / 4 / 5 : libxslt (CESA-2008:0287)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxslt packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

libxslt is a C library, based on libxml, for parsing of XML files into
other textual formats (eg HTML, plain text and other XML
representations of the underlying data) It uses the standard XSLT
stylesheet transformation mechanism and, being written in plain ANSI
C, is designed to be simple to incorporate into other applications

Anthony de Almeida Lopes reported the libxslt library did not properly
process long 'transformation match' conditions in the XSL stylesheet
files. An attacker could create a malicious XSL file that would cause
a crash, or, possibly, execute and arbitrary code with the privileges
of the application using libxslt library to perform XSL
transformations. (CVE-2008-1767)

All users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014920.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d4792bc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014921.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fbb6f292"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014922.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ecdcaf9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014923.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d924c26"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014929.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e15aebb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014930.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?315b6946"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014933.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58a7ced9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014934.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a36cb756"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"libxslt-1.0.33-6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxslt-devel-1.0.33-6")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libxslt-python-1.0.33-6")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libxslt-1.1.11-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxslt-1.1.11-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libxslt-1.1.11-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libxslt-devel-1.1.11-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxslt-devel-1.1.11-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libxslt-devel-1.1.11-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libxslt-python-1.1.11-1.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libxslt-python-1.1.11-1.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libxslt-python-1.1.11-1.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libxslt-1.1.17-2.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxslt-devel-1.1.17-2.el5_1.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxslt-python-1.1.17-2.el5_1.1")) flag++;


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
