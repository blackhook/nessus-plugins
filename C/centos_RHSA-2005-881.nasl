#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:881 and 
# CentOS Errata and Security Advisory 2005:881 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21877);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0976", "CVE-2005-0448", "CVE-2005-3962");
  script_xref(name:"RHSA", value:"2005:881");

  script_name(english:"CentOS 3 : perl (CESA-2005:881)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Perl packages that fix security issues and bugs are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Perl is a high-level programming language commonly used for system
administration utilities and Web programming.

An integer overflow bug was found in Perl's format string processor.
It is possible for an attacker to cause perl to crash or execute
arbitrary code if the attacker is able to process a malicious format
string. This issue is only exploitable through a script wich passes
arbitrary untrusted strings to the format string processor. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-3962
to this issue.

Paul Szabo discovered a bug in the way Perl's File::Path::rmtree
module removed directory trees. If a local user has write permissions
to a subdirectory within the tree being removed by File::Path::rmtree,
it is possible for them to create setuid binary files. (CVE-2005-0448)

Solar Designer discovered several temporary file bugs in various Perl
modules. A local attacker could overwrite or create files as the user
running a Perl script that uses a vulnerable module. (CVE-2004-0976)

Users of Perl are advised to upgrade to these updated packages, which
contain backported patches to correct these issues as well as fixes
for several bugs."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012484.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3499679"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012485.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2e0e61e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-December/012491.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad8f78f3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-DB_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"perl-5.8.0-90.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"perl-CGI-2.89-90.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"perl-CPAN-1.61-90.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"perl-DB_File-1.806-90.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"perl-suidperl-5.8.0-90.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CGI / perl-CPAN / perl-DB_File / perl-suidperl");
}
