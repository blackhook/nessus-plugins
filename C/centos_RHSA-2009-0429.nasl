#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0429 and 
# CentOS Errata and Security Advisory 2009:0429 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38897);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_bugtraq_id(34571);
  script_xref(name:"RHSA", value:"2009:0429");

  script_name(english:"CentOS 4 / 5 : cups (CESA-2009:0429)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Common UNIX(r) Printing System (CUPS) provides a portable printing
layer for UNIX operating systems.

Multiple integer overflow flaws were found in the CUPS JBIG2 decoder.
An attacker could create a malicious PDF file that would cause CUPS to
crash or, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2009-0147, CVE-2009-1179)

Multiple buffer overflow flaws were found in the CUPS JBIG2 decoder.
An attacker could create a malicious PDF file that would cause CUPS to
crash or, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2009-0146, CVE-2009-1182)

Multiple flaws were found in the CUPS JBIG2 decoder that could lead to
the freeing of arbitrary memory. An attacker could create a malicious
PDF file that would cause CUPS to crash or, potentially, execute
arbitrary code as the 'lp' user if the file was printed.
(CVE-2009-0166, CVE-2009-1180)

Multiple input validation flaws were found in the CUPS JBIG2 decoder.
An attacker could create a malicious PDF file that would cause CUPS to
crash or, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2009-0800)

An integer overflow flaw, leading to a heap-based buffer overflow, was
discovered in the Tagged Image File Format (TIFF) decoding routines
used by the CUPS image-converting filters, 'imagetops' and
'imagetoraster'. An attacker could create a malicious TIFF file that
could, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2009-0163)

Multiple denial of service flaws were found in the CUPS JBIG2 decoder.
An attacker could create a malicious PDF file that would cause CUPS to
crash when printed. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

Red Hat would like to thank Aaron Sigel, Braden Thomas and Drew Yao of
the Apple Product Security team, and Will Dormann of the CERT/CC for
responsibly reporting these flaws.

Users of cups are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, the cupsd daemon will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015778.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddf82a0f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015794.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73d4d874"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015795.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29569a49"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015916.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0271ac67"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015917.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26622be5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-1.1.22-0.rc1.9.27.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-1.1.22-0.rc1.9.27.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-1.1.22-0.rc1.9.27.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-devel-1.1.22-0.rc1.9.27.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-devel-1.1.22-0.rc1.9.27.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-devel-1.1.22-0.rc1.9.27.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"cups-libs-1.1.22-0.rc1.9.27.el4_7.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cups-libs-1.1.22-0.rc1.9.27.c4.5")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"cups-libs-1.1.22-0.rc1.9.27.el4_7.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"cups-1.3.7-8.el5_3.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.3.7-8.el5_3.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.3.7-8.el5_3.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.3.7-8.el5_3.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs / cups-lpd");
}
