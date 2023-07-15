#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2480 and 
# Oracle Linux Security Advisory ELSA-2017-2480 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102516);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-9800");
  script_xref(name:"RHSA", value:"2017:2480");

  script_name(english:"Oracle Linux 7 : subversion (ELSA-2017-2480)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:2480 :

An update for subversion is now available for Red Hat Enterprise Linux
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-August/007127.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_dav_svn-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-devel-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-gnome-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-javahl-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-kde-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-libs-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-perl-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-python-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-ruby-1.7.14-11.el7_4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"subversion-tools-1.7.14-11.el7_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-gnome / etc");
}
