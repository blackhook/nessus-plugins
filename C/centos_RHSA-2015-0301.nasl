#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0301 and 
# CentOS Errata and Security Advisory 2015:0301 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81886);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-9273");
  script_xref(name:"RHSA", value:"2015:0301");

  script_name(english:"CentOS 7 : hivex (CESA-2015:0301)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hivex packages that fix one security issue, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Hive files are undocumented binary files that Windows uses to store
the Windows Registry on disk. Hivex is a library that can read and
write to these files.

It was found that hivex attempted to read beyond its allocated buffer
when reading a hive file with a very small size or with a truncated or
improperly formatted content. An attacker able to supply a specially
crafted hive file to an application using the hivex library could
possibly use this flaw to execute arbitrary code with the privileges
of the user running that application. (CVE-2014-9273)

Red Hat would like to thank Mahmoud Al-Qudsi of NeoSmart Technologies
for reporting this issue.

The hivex package has been upgraded to upstream version 1.3.10, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#1023978)

This update also fixes the following bugs :

* Due to an error in the hivex_value_data_cell_offset() function, the
hivex utility could, in some cases, print an 'Argument list is too
long' message and terminate unexpectedly when processing hive files
from the Windows Registry. This update fixes the underlying code and
hivex now processes hive files as expected. (BZ#1145056)

* A typographical error in the Win::Hivex.3pm manual page has been
corrected. (BZ#1099286)

Users of hivex are advised to upgrade to these updated packages, which
correct these issues and adds these enhancements."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-March/001583.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a9901e96"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hivex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9273");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"hivex-devel-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-hivex-devel-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-hivex-1.3.10-5.7.el7")) flag++;


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
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hivex / hivex-devel / ocaml-hivex / ocaml-hivex-devel / perl-hivex / etc");
}
