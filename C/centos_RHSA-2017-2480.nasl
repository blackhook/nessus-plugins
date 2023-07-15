#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2480 and 
# CentOS Errata and Security Advisory 2017:2480 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102768);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-9800");
  script_xref(name:"RHSA", value:"2017:2480");

  script_name(english:"CentOS 7 : subversion (CESA-2017:2480)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for subversion is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.

Security Fix(es) :

* A shell command injection flaw related to the handling of 'svn+ssh'
URLs has been discovered in Subversion. An attacker could use this
flaw to execute shell commands with the privileges of the user running
the Subversion client, for example when performing a 'checkout' or
'update' action on a malicious repository, or a legitimate repository
containing a malicious commit. (CVE-2017-9800)

Red Hat would like to thank the Subversion Team for reporting this
issue."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2017-August/004684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df98ab8d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9800");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/25");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mod_dav_svn-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-devel-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-gnome-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-javahl-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-kde-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-libs-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-perl-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-python-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-ruby-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subversion-tools-1.7.14-11.el7_4")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-gnome / etc");
}
