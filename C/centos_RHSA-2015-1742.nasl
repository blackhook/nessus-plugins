#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1742 and 
# CentOS Errata and Security Advisory 2015:1742 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86510);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-0248", "CVE-2015-0251", "CVE-2015-3184", "CVE-2015-3187");
  script_xref(name:"RHSA", value:"2015:1742");

  script_name(english:"CentOS 7 : subversion (CESA-2015:1742)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated subversion packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

An assertion failure flaw was found in the way the SVN server
processed certain requests with dynamically evaluated revision
numbers. A remote attacker could use this flaw to cause the SVN server
(both svnserve and httpd with the mod_dav_svn module) to crash.
(CVE-2015-0248)

It was found that the mod_authz_svn module did not properly restrict
anonymous access to Subversion repositories under certain
configurations when used with Apache httpd 2.4.x. This could allow a
user to anonymously access files in a Subversion repository, which
should only be accessible to authenticated users. (CVE-2015-3184)

It was found that the mod_dav_svn module did not properly validate the
svn:author property of certain requests. An attacker able to create
new revisions could use this flaw to spoof the svn:author property.
(CVE-2015-0251)

It was found that when an SVN server (both svnserve and httpd with the
mod_dav_svn module) searched the history of a file or a directory, it
would disclose its location in the repository if that file or
directory was not readable (for example, if it had been moved).
(CVE-2015-3187)

Red Hat would like to thank the Apache Software Foundation for
reporting these issues. Upstream acknowledges Evgeny Kotkov of
VisualSVN as the original reporter of CVE-2015-0248 and CVE-2015-0251,
and C. Michael Pilato of CollabNet as the original reporter of
CVE-2015-3184 and CVE-2015-3187 flaws.

All subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, for the update to take effect, you must restart
the httpd daemon, if you are using mod_dav_svn, and the svnserve
daemon, if you are serving Subversion repositories via the svn://
protocol."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-September/021377.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af0d0b99"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0248");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mod_dav_svn-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-devel-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-gnome-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-javahl-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-kde-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-libs-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-perl-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-python-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-ruby-1.7.14-7.el7_1.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-tools-1.7.14-7.el7_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-gnome / etc");
}
