#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0559 and 
# CentOS Errata and Security Advisory 2017:0559 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97837);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-5139", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-7163", "CVE-2016-9675");
  script_xref(name:"RHSA", value:"2017:0559");

  script_name(english:"CentOS 6 : openjpeg (CESA-2017:0559)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for openjpeg is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenJPEG is an open source library for reading and writing image files
in JPEG2000 format.

Security Fix(es) :

* Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in OpenJPEG. A specially crafted JPEG2000 image
could cause an application using OpenJPEG to crash or, potentially,
execute arbitrary code. (CVE-2016-5139, CVE-2016-5158, CVE-2016-5159,
CVE-2016-7163)

* A vulnerability was found in the patch for CVE-2013-6045 for
OpenJPEG. A specially crafted JPEG2000 image, when read by an
application using OpenJPEG, could cause heap-based buffer overflows
leading to a crash or, potentially, arbitrary code execution.
(CVE-2016-9675)

The CVE-2016-9675 issue was discovered by Doran Moppert (Red Hat
Product Security)."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-March/022343.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f186d11b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openjpeg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5139");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openjpeg-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/21");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"openjpeg-1.3-16.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openjpeg-devel-1.3-16.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openjpeg-libs-1.3-16.el6_8")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg / openjpeg-devel / openjpeg-libs");
}
