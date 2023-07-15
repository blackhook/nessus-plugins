#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0760 and 
# CentOS Errata and Security Advisory 2016:0760 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91167);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-3538", "CVE-2014-3587", "CVE-2014-3710", "CVE-2014-8116", "CVE-2014-8117", "CVE-2014-9620", "CVE-2014-9653");
  script_xref(name:"RHSA", value:"2016:0760");

  script_name(english:"CentOS 6 : file (CESA-2016:0760)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for file is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The file command is used to identify a particular file according to
the type of data the file contains. It can identify many different
file types, including Executable and Linkable Format (ELF) binary
files, system libraries, RPM packages, and different graphics formats.

Security Fix(es) :

* Multiple flaws were found in the file regular expression rules for
detecting various files. A remote attacker could use these flaws to
cause file to consume an excessive amount of CPU. (CVE-2014-3538)

* A denial of service flaw was found in the way file parsed certain
Composite Document Format (CDF) files. A remote attacker could use
this flaw to crash file via a specially crafted CDF file.
(CVE-2014-3587)

* Multiple flaws were found in the way file parsed Executable and
Linkable Format (ELF) files. A remote attacker could use these flaws
to cause file to crash, disclose portions of its memory, or consume an
excessive amount of system resources. (CVE-2014-3710, CVE-2014-8116,
CVE-2014-8117, CVE-2014-9620, CVE-2014-9653)

Red Hat would like to thank Thomas Jarosch (Intra2net AG) for
reporting CVE-2014-8116 and CVE-2014-8117. The CVE-2014-3538 issue was
discovered by Jan Kaluza (Red Hat Web Stack Team) and the
CVE-2014-3710 issue was discovered by Francisco Alonso (Red Hat
Product Security).

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.8 Release Notes and Red Hat Enterprise Linux 6.8
Technical Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-May/002805.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?990dcc10"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected file packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9653");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:file-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-6", reference:"file-5.04-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"file-devel-5.04-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"file-libs-5.04-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"file-static-5.04-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-magic-5.04-30.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-devel / file-libs / file-static / python-magic");
}
