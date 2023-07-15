#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0431 and 
# CentOS Errata and Security Advisory 2009:0431 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38898);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_bugtraq_id(34568);
  script_xref(name:"RHSA", value:"2009:0431");

  script_name(english:"CentOS 4 / 5 : kdegraphics (CESA-2009:0431)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdegraphics packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kdegraphics packages contain applications for the K Desktop
Environment, including KPDF, a viewer for Portable Document Format
(PDF) files.

Multiple integer overflow flaws were found in KPDF's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause KPDF to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0147, CVE-2009-1179)

Multiple buffer overflow flaws were found in KPDF's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause KPDF to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0146, CVE-2009-1182)

Multiple flaws were found in KPDF's JBIG2 decoder that could lead to
the freeing of arbitrary memory. An attacker could create a malicious
PDF file that would cause KPDF to crash or, potentially, execute
arbitrary code when opened. (CVE-2009-0166, CVE-2009-1180)

Multiple input validation flaws were found in KPDF's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause KPDF to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0800)

Multiple denial of service flaws were found in KPDF's JBIG2 decoder.
An attacker could create a malicious PDF that would cause KPDF to
crash when opened. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

Red Hat would like to thank Braden Thomas and Drew Yao of the Apple
Product Security team, and Will Dormann of the CERT/CC for responsibly
reporting these flaws.

Users are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015780.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee94bba5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015867.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3191add"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015868.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?673d5641"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015920.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abdce73d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015921.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3276b833"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", reference:"kdegraphics-3.3.1-13.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdegraphics-devel-3.3.1-13.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"kdegraphics-3.5.4-12.el5_3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdegraphics-devel-3.5.4-12.el5_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdegraphics / kdegraphics-devel");
}
