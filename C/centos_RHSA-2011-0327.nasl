#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0327 and 
# CentOS Errata and Security Advisory 2011:0327 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53425);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-0715");
  script_bugtraq_id(46734);
  script_xref(name:"RHSA", value:"2011:0327");

  script_name(english:"CentOS 5 : subversion (CESA-2011:0327)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subversion packages that fix one security issue and one bug
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module processed certain requests to lock working copy paths in a
repository. A remote attacker could issue a lock request that could
cause the httpd process serving the request to crash. (CVE-2011-0715)

Red Hat would like to thank Hyrum Wright of the Apache Subversion
project for reporting this issue. Upstream acknowledges Philip Martin,
WANdisco, Inc. as the original reporter.

This update also fixes the following bug :

* A regression was found in the handling of repositories which do not
have a 'db/fsfs.conf' file. The 'svnadmin hotcopy' command would fail
when trying to produce a copy of such a repository. This command has
been fixed to ignore the absence of the 'fsfs.conf' file. The
'svnadmin hotcopy' command will now succeed for this type of
repository. (BZ#681522)

All Subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, you must restart the httpd daemon, if you are
using mod_dav_svn, for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017286.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34b9181b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2adf7f0e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"mod_dav_svn-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-devel-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-javahl-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-perl-1.6.11-7.el5_6.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-ruby-1.6.11-7.el5_6.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-javahl / etc");
}
