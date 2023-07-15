#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2504 and 
# CentOS Errata and Security Advisory 2015:2504 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87173);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5302");
  script_xref(name:"RHSA", value:"2015:2504");

  script_name(english:"CentOS 6 : libreport (CESA-2015:2504)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libreport packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

libreport provides an API for reporting different problems in
applications to different bug targets, such as Bugzilla, FTP, and
Trac. ABRT (Automatic Bug Reporting Tool) uses libreport.

It was found that ABRT may have exposed unintended information to Red
Hat Bugzilla during crash reporting. A bug in the libreport library
caused changes made by a user in files included in a crash report to
be discarded. As a result, Red Hat Bugzilla attachments may contain
data that was not intended to be made public, including host names, IP
addresses, or command line options. (CVE-2015-5302)

This flaw did not affect default installations of ABRT on Red Hat
Enterprise Linux as they do not post data to Red Hat Bugzilla. This
feature can however be enabled, potentially impacting modified ABRT
instances.

As a precaution, Red Hat has identified bugs filed by such non-default
Red Hat Enterprise Linux users of ABRT and marked them private.

This issue was discovered by Bastien Nocera of Red Hat.

All users of libreport are advised to upgrade to these updated
packages, which corrects this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-December/021513.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5507eb2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreport packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5302");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-bugzilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-kerneloops");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-reportuploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-rhtsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-plugin-ureport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libreport-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"libreport-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-cli-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-compat-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-devel-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-filesystem-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-gtk-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-gtk-devel-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-newt-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-bugzilla-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-kerneloops-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-logger-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-mailx-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-reportuploader-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-rhtsupport-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-plugin-ureport-2.0.9-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libreport-python-2.0.9-25.el6.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreport / libreport-cli / libreport-compat / libreport-devel / etc");
}
