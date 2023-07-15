#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0458 and 
# CentOS Errata and Security Advisory 2009:0458 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38901);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-3606");
  script_bugtraq_id(34568, 34791);
  script_xref(name:"RHSA", value:"2009:0458");

  script_name(english:"CentOS 4 : gpdf (CESA-2009:0458)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gpdf package that fixes multiple security issues is now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

GPdf is a viewer for Portable Document Format (PDF) files.

Multiple integer overflow flaws were found in GPdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause GPdf to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0147, CVE-2009-1179)

Multiple buffer overflow flaws were found in GPdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause GPdf to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0146, CVE-2009-1182)

Multiple flaws were found in GPdf's JBIG2 decoder that could lead to
the freeing of arbitrary memory. An attacker could create a malicious
PDF file that would cause GPdf to crash or, potentially, execute
arbitrary code when opened. (CVE-2009-0166, CVE-2009-1180)

Multiple input validation flaws were found in GPdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause GPdf to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0800)

Multiple denial of service flaws were found in GPdf's JBIG2 decoder.
An attacker could create a malicious PDF that would cause GPdf to
crash when opened. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

Red Hat would like to thank Braden Thomas and Drew Yao of the Apple
Product Security team, and Will Dormann of the CERT/CC for responsibly
reporting these flaws.

Users are advised to upgrade to this updated package, which contains
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcf54077"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015924.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e369552a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015925.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aac6b724"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/22");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gpdf-2.8.2-7.7.2.el4_7.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gpdf-2.8.2-7.7.2.c4.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gpdf-2.8.2-7.7.2.el4_7.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gpdf");
}
