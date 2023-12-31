#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0523 and 
# CentOS Errata and Security Advisory 2012:0523 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58879);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-3048");
  script_bugtraq_id(52830);
  script_xref(name:"RHSA", value:"2012:0523");

  script_name(english:"CentOS 5 / 6 : libpng (CESA-2012:0523)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A heap-based buffer overflow flaw was found in the way libpng
processed tEXt chunks in PNG image files. An attacker could create a
specially crafted PNG image file that, when opened, could cause an
application using libpng to crash or, possibly, execute arbitrary code
with the privileges of the user running the application.
(CVE-2011-3048)

Users of libpng should upgrade to these updated packages, which
correct this issue. For Red Hat Enterprise Linux 5, they contain a
backported patch. For Red Hat Enterprise Linux 6, they upgrade libpng
to version 1.2.49. All running applications using libpng must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-April/018601.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ceb5389f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-April/018602.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?634ea5f3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3048");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"libpng-1.2.10-17.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpng-devel-1.2.10-17.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libpng-1.2.49-1.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpng-devel-1.2.49-1.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpng-static-1.2.49-1.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-devel / libpng-static");
}
