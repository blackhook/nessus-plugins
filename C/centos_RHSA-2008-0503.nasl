#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0503 and 
# CentOS Errata and Security Advisory 2008:0503 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33364);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361");
  script_bugtraq_id(29665, 29666, 29668, 29669);
  script_xref(name:"RHSA", value:"2008:0503");

  script_name(english:"CentOS 4 : xorg-x11 (CESA-2008:0503)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11 packages that fix several security issues are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The xorg-x11 packages contain X.Org, an open source implementation of
the X Window System. It provides the basic low-level functionality
that full-fledged graphical user interfaces are designed upon.

An input validation flaw was discovered in X.org's Security and Record
extensions. A malicious authorized client could exploit this issue to
cause a denial of service (crash) or, potentially, execute arbitrary
code with root privileges on the X.Org server. (CVE-2008-1377)

Multiple integer overflow flaws were found in X.org's Render
extension. A malicious authorized client could exploit these issues to
cause a denial of service (crash) or, potentially, execute arbitrary
code with root privileges on the X.Org server. (CVE-2008-2360,
CVE-2008-2361)

An input validation flaw was discovered in X.org's MIT-SHM extension.
A client connected to the X.org server could read arbitrary server
memory. This could result in the sensitive data of other users of the
X.org server being disclosed. (CVE-2008-1379)

Users of xorg-x11 should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/014985.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df92451d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/015044.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e33299b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/015045.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11e4ea51"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-deprecated-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-deprecated-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/02");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Xdmx-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Xnest-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-Xvfb-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-devel-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-doc-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-font-utils-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-libs-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-sdk-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-tools-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-twm-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-xauth-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-xdm-6.8.2-1.EL.33.0.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"xorg-x11-xfs-6.8.2-1.EL.33.0.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11 / xorg-x11-Mesa-libGL / xorg-x11-Mesa-libGLU / etc");
}
