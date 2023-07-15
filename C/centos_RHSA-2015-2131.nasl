#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2131 and 
# CentOS Errata and Security Advisory 2015:2131 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87132);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-8182", "CVE-2015-3276");
  script_xref(name:"RHSA", value:"2015:2131");

  script_name(english:"CentOS 7 : openldap (CESA-2015:2131)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue, several bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols used to access and maintain distributed directory
information services over an IP network. The openldap packages contain
configuration files, libraries, and documentation for OpenLDAP.

A flaw was found in the way OpenLDAP parsed OpenSSL-style cipher
strings. As a result, OpenLDAP could potentially use ciphers that were
not intended to be enabled. (CVE-2015-3276)

This issue was discovered by Martin Poole of the Red Hat Software
Maintenance Engineering group.

The openldap packages have been upgraded to upstream version 2.4.40,
which provides a number of bug fixes and one enhancement over the
previous version :

* The ORDERING matching rules have been added to the ppolicy attribute
type descriptions.

* The server no longer terminates unexpectedly when processing SRV
records.

* Missing objectClass information has been added, which enables the
user to modify the front-end configuration by standard means.

(BZ#1147982)

This update also fixes the following bugs :

* Previously, OpenLDAP did not properly handle a number of
simultaneous updates. As a consequence, sending a number of parallel
update requests to the server could cause a deadlock. With this
update, a superfluous locking mechanism causing the deadlock has been
removed, thus fixing the bug. (BZ#1125152)

* The httpd service sometimes terminated unexpectedly with a
segmentation fault on the libldap library unload. The underlying
source code has been modified to prevent a bad memory access error
that caused the bug to occur. As a result, httpd no longer crashes in
this situation. (BZ#1158005)

* After upgrading the system from Red Hat Enterprise Linux 6 to Red
Hat Enterprise Linux 7, symbolic links to certain libraries
unexpectedly pointed to locations belonging to the openldap-devel
package. If the user uninstalled openldap-devel, the symbolic links
were broken and the 'rpm -V openldap' command sometimes produced
errors. With this update, the symbolic links no longer get broken in
the described situation. If the user downgrades openldap to version
2.4.39-6 or earlier, the symbolic links might break. After such
downgrade, it is recommended to verify that the symbolic links did not
break. To do this, make sure the yum-plugin-verify package is
installed and obtain the target libraries by running the 'rpm -V
openldap' or 'yum verify openldap' command. (BZ#1230263)

In addition, this update adds the following enhancement :

* OpenLDAP clients now automatically choose the Network Security
Services (NSS) default cipher suites for communication with the
server. It is no longer necessary to maintain the default cipher
suites manually in the OpenLDAP source code. (BZ#1245279)

All openldap users are advised to upgrade to these updated packages,
which correct these issues and add this enhancement."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3cc38519"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3276");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-2.4.40-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-clients-2.4.40-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-devel-2.4.40-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-servers-2.4.40-8.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openldap-servers-sql-2.4.40-8.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap / openldap-clients / openldap-devel / openldap-servers / etc");
}
