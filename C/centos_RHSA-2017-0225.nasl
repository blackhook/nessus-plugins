#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0225 and 
# CentOS Errata and Security Advisory 2017:0225 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96929);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-8870", "CVE-2016-5652", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9540");
  script_xref(name:"RHSA", value:"2017:0225");

  script_name(english:"CentOS 6 / 7 : libtiff (CESA-2017:0225)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libtiff is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Security Fix(es) :

* Multiple flaws have been discovered in libtiff. A remote attacker
could exploit these flaws to cause a crash or memory corruption and,
possibly, execute arbitrary code by tricking an application linked
against libtiff into processing specially crafted files.
(CVE-2016-9533, CVE-2016-9534, CVE-2016-9535)

* Multiple flaws have been discovered in various libtiff tools
(tiff2pdf, tiffcrop, tiffcp, bmp2tiff). By tricking a user into
processing a specially crafted file, a remote attacker could exploit
these flaws to cause a crash or memory corruption and, possibly,
execute arbitrary code with the privileges of the user running the
libtiff tool. (CVE-2015-8870, CVE-2016-5652, CVE-2016-9540,
CVE-2016-9537, CVE-2016-9536)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-February/022259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e90f7f98"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-February/022261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdca795b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9533");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"libtiff-3.9.4-21.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtiff-devel-3.9.4-21.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtiff-static-3.9.4-21.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtiff-4.0.3-27.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtiff-devel-4.0.3-27.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtiff-static-4.0.3-27.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libtiff-tools-4.0.3-27.el7_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-devel / libtiff-static / libtiff-tools");
}
