#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1159 and 
# CentOS Errata and Security Advisory 2009:1159 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40344);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2285", "CVE-2009-2347");
  script_bugtraq_id(35451, 35652);
  script_xref(name:"RHSA", value:"2009:1159");

  script_name(english:"CentOS 3 / 5 : libtiff (CESA-2009:1159)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtiff packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Several integer overflow flaws, leading to heap-based buffer
overflows, were found in various libtiff color space conversion tools.
An attacker could create a specially crafted TIFF file, which once
opened by an unsuspecting user, would cause the conversion tool to
crash or, potentially, execute arbitrary code with the privileges of
the user running the tool. (CVE-2009-2347)

A buffer underwrite flaw was found in libtiff's Lempel-Ziv-Welch (LZW)
compression algorithm decoder. An attacker could create a specially
crafted LZW-encoded TIFF file, which once opened by an unsuspecting
user, would cause an application linked with libtiff to access an
out-of-bounds memory location, leading to a denial of service
(application crash). (CVE-2009-2285)

The CVE-2009-2347 flaws were discovered by Tielei Wang from
ICST-ERCIS, Peking University.

All libtiff users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, all applications linked with the libtiff library (such as
Konqueror) must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60a75003"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?792f9f81"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15b830cb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016043.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ba7505a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/23");
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
if (! preg(pattern:"^(3|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libtiff-3.5.7-33.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libtiff-3.5.7-33.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libtiff-devel-3.5.7-33.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libtiff-devel-3.5.7-33.el3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libtiff-3.8.2-7.el5_3.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtiff-devel-3.8.2-7.el5_3.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-devel");
}
