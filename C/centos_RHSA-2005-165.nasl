#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:165 and 
# CentOS Errata and Security Advisory 2005:165 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21920);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0175");
  script_xref(name:"RHSA", value:"2005:165");

  script_name(english:"CentOS 4 : rsh (CESA-2005:165)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rsh packages that fix various bugs and a theoretical security
issue are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team

The rsh package contains a set of programs that allow users to run
commands on remote machines, login to other machines, and copy files
between machines, using the rsh, rlogin, and rcp commands. All three
of these commands use rhosts-style authentication.

The rcp protocol allows a server to instruct a client to write to
arbitrary files outside of the current directory. This could
potentially cause a security issue if a user uses rcp to copy files
from a malicious server. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0175 to this
issue.

These updated packages also address the following bugs :

The rlogind server reported 'SIGCHLD set to SIG_IGN but calls wait()'
message to the system log because the original BSD code was ported
incorrectly to linux.

The rexecd server did not function on systems where client hostnames
were not in the DNS service, because server code called
gethostbyaddr() for each new connection.

The rcp command incorrectly used the 'errno' variable and produced
erroneous error messages.

The rexecd command ignored settings in the /etc/security/limits file,
because the PAM session was incorrectly initialized.

All users of rsh should upgrade to these updated packages, which
resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011799.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1184cc5a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011801.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb08b90e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd2fddbf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rsh packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rsh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
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
if (rpm_check(release:"CentOS-4", reference:"rsh-0.17-25.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"rsh-server-0.17-25.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rsh / rsh-server");
}
