#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1237 and 
# CentOS Errata and Security Advisory 2016:1237 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91636);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-8895", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2016-5118", "CVE-2016-5239", "CVE-2016-5240");
  script_xref(name:"RHSA", value:"2016:1237");

  script_name(english:"CentOS 6 / 7 : ImageMagick (CESA-2016:1237)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ImageMagick is now available for Red Hat Enterprise
Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

[Updated 18 July 2016] This advisory has been updated to push packages
into the Red Hat Enterprise Linux 6 Desktop channels. The packages
included in this revised update have not been changed in any way from
the packages included in the original advisory.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

Security Fix(es) :

* It was discovered that ImageMagick did not properly sanitize certain
input before using it to invoke processes. A remote attacker could
create a specially crafted image that, when processed by an
application using ImageMagick or an unsuspecting user using the
ImageMagick utilities, would lead to arbitrary execution of shell
commands with the privileges of the user running the application.
(CVE-2016-5118)

* It was discovered that ImageMagick did not properly sanitize certain
input before passing it to the gnuplot delegate functionality. A
remote attacker could create a specially crafted image that, when
processed by an application using ImageMagick or an unsuspecting user
using the ImageMagick utilities, would lead to arbitrary execution of
shell commands with the privileges of the user running the
application. (CVE-2016-5239)

* Multiple flaws have been discovered in ImageMagick. A remote
attacker could, for example, create specially crafted images that,
when processed by an application using ImageMagick or an unsuspecting
user using the ImageMagick utilities, would result in a memory
corruption and, potentially, execution of arbitrary code, a denial of
service, or an application crash. (CVE-2015-8896, CVE-2015-8895,
CVE-2016-5240, CVE-2015-8897, CVE-2015-8898)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-June/021909.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b4b29fb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-June/021910.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2beaaffa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected imagemagick packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5118");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-c++-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-c++-devel-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-devel-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-doc-6.7.2.7-5.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ImageMagick-perl-6.7.2.7-5.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-c++-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-c++-devel-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-devel-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-doc-6.7.8.9-15.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ImageMagick-perl-6.7.8.9-15.el7_2")) flag++;


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
