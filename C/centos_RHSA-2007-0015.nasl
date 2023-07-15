#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0015 and 
# CentOS Errata and Security Advisory 2007:0015 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24357);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-2440", "CVE-2006-5456", "CVE-2006-5868");
  script_bugtraq_id(20707);
  script_xref(name:"RHSA", value:"2007:0015");

  script_name(english:"CentOS 3 / 4 : ImageMagick (CESA-2007:0015)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that correct several security issues are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

Several security flaws were discovered in the way ImageMagick decodes
DCM, PALM, and SGI graphic files. An attacker may be able to execute
arbitrary code on a victim's machine if they were able to trick the
victim into opening a specially crafted image file (CVE-2006-5456,
CVE-2006-5868).

A heap overflow flaw was found in ImageMagick. An attacker may be able
to execute arbitrary code on a victim's machine if they were able to
trick the victim into opening a specially crafted file
(CVE-2006-2440). This issue only affected the version of ImageMagick
distributed with Red Hat Enterprise Linux 4.

Users of ImageMagick should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013528.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd6a9ac7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013529.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20bc4185"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013530.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb1fc6af"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22a2b3ab"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc8488be"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-February/013541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8ad0c60"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-5.5.6-24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-c++-5.5.6-24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-c++-devel-5.5.6-24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-devel-5.5.6-24")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ImageMagick-perl-5.5.6-24")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ImageMagick-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ImageMagick-c++-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ImageMagick-c++-devel-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ImageMagick-devel-6.0.7.1-16.0.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ImageMagick-perl-6.0.7.1-16.0.3")) flag++;


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
