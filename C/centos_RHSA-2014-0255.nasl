#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0255 and 
# CentOS Errata and Security Advisory 2014:0255 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72866);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-1968", "CVE-2013-2112", "CVE-2014-0032");
  script_bugtraq_id(60264, 60267, 65434);
  script_xref(name:"RHSA", value:"2014:0255");

  script_name(english:"CentOS 5 / 6 : subversion (CESA-2014:0255)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subversion packages that fix three security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

A flaw was found in the way the mod_dav_svn module handled OPTIONS
requests. A remote attacker with read access to an SVN repository
served via HTTP could use this flaw to cause the httpd process that
handled such a request to crash. (CVE-2014-0032)

A flaw was found in the way Subversion handled file names with newline
characters when the FSFS repository format was used. An attacker with
commit access to an SVN repository could corrupt a revision by
committing a specially crafted file. (CVE-2013-1968)

A flaw was found in the way the svnserve tool of Subversion handled
remote client network connections. An attacker with read access to an
SVN repository served via svnserve could use this flaw to cause the
svnserve daemon to exit, leading to a denial of service.
(CVE-2013-2112)

All subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, for the update to take effect, you must restart
the httpd daemon, if you are using mod_dav_svn, and the svnserve
daemon, if you are serving Subversion repositories via the svn://
protocol."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-March/020189.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01ae660a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-March/020190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0971779c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2112");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-svn2cl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"mod_dav_svn-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-devel-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-javahl-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-perl-1.6.11-12.el5_10")) flag++;
if (rpm_check(release:"CentOS-5", reference:"subversion-ruby-1.6.11-12.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"mod_dav_svn-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-devel-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-gnome-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-javahl-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-kde-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-perl-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-ruby-1.6.11-10.el6_5")) flag++;
if (rpm_check(release:"CentOS-6", reference:"subversion-svn2cl-1.6.11-10.el6_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-gnome / etc");
}
