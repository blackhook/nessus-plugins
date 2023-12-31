#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0052 and 
# CentOS Errata and Security Advisory 2006:0052 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21976);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2917");
  script_bugtraq_id(14977);
  script_xref(name:"RHSA", value:"2006:0052");

  script_name(english:"CentOS 4 : squid (CESA-2006:0052)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squid package that fixes a security vulnerability as well
as several issues is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Squid is a high-performance proxy caching server for Web clients,
supporting FTP, gopher, and HTTP data objects.

A denial of service flaw was found in the way squid processes certain
NTLM authentication requests. It is possible for a remote attacker to
crash the Squid server by sending a specially crafted NTLM
authentication request. The Common Vulnerabilities and Exposures
project (cve.mitre.org) assigned the name CVE-2005-2917 to this issue.

The following issues have also been fixed in this update :

* An error introduced in squid-2.5.STABLE6-3.4E.12 can crash Squid
when a user visits a site that has a bit longer DNS record.

* An error introduced in the old package prevented Squid from
returning correct information about large file systems. The new
package is compiled with the IDENT lookup support so that users who
want to use it do not have to recompile it.

* Some authentication helpers needed SETUID rights but did not have
them. If administrators wanted to use cache administrator, they had to
change the SETUID bit manually. The updated package sets this bit so
the new package can be updated without manual intervention from
administrators.

* Squid could not handle a reply from an HTTP server when the reply
began with the new-line character.

* An issue was discovered when a reply from an HTTP server was not
HTTP 1.0 or 1.1 compliant.

* The updated package keeps user-defined error pages when the package
is updated and it adds new ones.

All users of squid should upgrade to this updated package, which
resolves these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012704.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77b0fa65"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012728.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e137b0d6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012735.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5241de4e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/10");
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
if (rpm_check(release:"CentOS-4", reference:"squid-2.5.STABLE6-3.4E.12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
