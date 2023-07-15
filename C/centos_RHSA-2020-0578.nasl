#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2020:0578 and 
# CentOS Errata and Security Advisory 2020:0578 respectively.
#

include('compat.inc');

if (description)
{
  script_id(134091);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2019-16865", "CVE-2020-5312");
  script_xref(name:"RHSA", value:"2020:0578");

  script_name(english:"CentOS 7 : python-pillow (CESA-2020:0578)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for python-pillow is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The python-pillow packages contain a Python image processing library
that provides extensive file format support, an efficient internal
representation, and powerful image-processing capabilities.

Security Fix(es) :

* python-pillow: improperly restricted operations on memory buffer in
libImaging/PcxDecode.c (CVE-2020-5312)

* python-pillow: reading specially crafted image files leads to
allocation of large amounts of memory and denial of service
(CVE-2019-16865)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  # https://lists.centos.org/pipermail/centos-announce/2020-February/035646.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ea2b17b");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pillow packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5312");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pillow-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pillow-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pillow-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pillow-sane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pillow-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-pillow-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-pillow-devel-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-pillow-doc-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-pillow-qt-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-pillow-sane-2.0.0-20.gitd1c6db8.el7_7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-pillow-tk-2.0.0-20.gitd1c6db8.el7_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pillow / python-pillow-devel / python-pillow-doc / etc");
}
