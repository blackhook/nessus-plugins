#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0653 and 
# CentOS Errata and Security Advisory 2010:0653 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48745);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-1882");
  script_bugtraq_id(35111);
  script_xref(name:"RHSA", value:"2010:0653");

  script_name(english:"CentOS 4 : ImageMagick (CESA-2010:0653)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that fix one security issue are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the ImageMagick routine responsible for creating X11 images.
An attacker could create a specially crafted image file that, when
opened by a victim, would cause ImageMagick to crash or, potentially,
execute arbitrary code. (CVE-2009-1882)

Users of ImageMagick are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. All running
instances of ImageMagick must be restarted for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016940.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dd259cf"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016941.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d972548e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/26");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-c++-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-c++-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-c++-devel-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-devel-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-devel-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ImageMagick-perl-6.0.7.1-20.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ImageMagick-perl-6.0.7.1-20.el4_8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
