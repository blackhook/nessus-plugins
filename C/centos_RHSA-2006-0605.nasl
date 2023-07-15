#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0605 and 
# CentOS Errata and Security Advisory 2006:0605 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22278);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0155", "CVE-2006-3813");
  script_bugtraq_id(12426);
  script_xref(name:"RHSA", value:"2006:0605");

  script_name(english:"CentOS 4 : perl (CESA-2006:0605)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Perl packages that fix security a security issue are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Perl is a high-level programming language commonly used for system
administration utilities and Web programming.

Kevin Finisterre discovered a flaw in sperl, the Perl setuid wrapper,
which can cause debugging information to be logged to arbitrary files.
By setting an environment variable, a local user could cause sperl to
create, as root, files with arbitrary filenames, or append the
debugging information to existing files. (CVE-2005-0155)

A fix for this issue was first included in the update RHSA-2005:103
released in February 2005. However the patch to correct this issue was
dropped from the update RHSA-2005:674 made in October 2005. This
regression has been assigned CVE-2006-3813.

Users of Perl are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1724583"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013146.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?70d19609"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013176.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bce6c173"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"perl-5.8.5-36.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"perl-suidperl-5.8.5-36.RHEL4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-suidperl");
}
