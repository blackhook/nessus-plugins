#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0128 and 
# CentOS Errata and Security Advisory 2013:0128 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63573);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-3359", "CVE-2013-7347");
  script_bugtraq_id(57322);
  script_xref(name:"RHSA", value:"2013:0128");

  script_name(english:"CentOS 5 : conga (CESA-2013:0128)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated conga packages that fix one security issue, multiple bugs, and
add two enhancements are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Conga project is a management system for remote workstations. It
consists of luci, which is a secure web-based front end, and ricci,
which is a secure daemon that dispatches incoming messages to
underlying management modules.

It was discovered that luci stored usernames and passwords in session
cookies. This issue prevented the session inactivity timeout feature
from working correctly, and allowed attackers able to get access to a
session cookie to obtain the victim's authentication credentials.
(CVE-2012-3359)

Red Hat would like to thank George Hedfors of Cybercom Sweden East AB
for reporting this issue.

This update also fixes the following bugs :

* Prior to this update, luci did not allow the fence_apc_snmp agent to
be configured. As a consequence, users could not configure or view an
existing configuration for fence_apc_snmp. This update adds a new
screen that allows fence_apc_snmp to be configured. (BZ#832181)

* Prior to this update, luci did not allow the SSL operation of the
fence_ilo fence agent to be enabled or disabled. As a consequence,
users could not configure or view an existing configuration for the
'ssl' attribute for fence_ilo. This update adds a checkbox to show
whether the SSL operation is enabled and allows users to edit that
attribute. (BZ#832183)

* Prior to this update, luci did not allow the 'identity_file'
attribute of the fence_ilo_mp fence agent to be viewed or edited. As a
consequence, users could not configure or view an existing
configuration for the 'identity_file' attribute of the fence_ilo_mp
fence agent. This update adds a text input box to show the current
state of the 'identity_file' attribute of fence_ilo_mp and allows
users to edit that attribute. (BZ#832185)

* Prior to this update, redundant files and directories remained on
the file system at /var/lib/luci/var/pts and
/usr/lib{,64}/luci/zope/var/pts when the luci package was uninstalled.
This update removes these files and directories when the luci package
is uninstalled. (BZ#835649)

* Prior to this update, the 'restart-disable' recovery policy was not
displayed in the recovery policy list from which users could select
when they configure a recovery policy for a failover domain. As a
consequence, the 'restart-disable' recovery policy could not be set
with the luci GUI. This update adds the 'restart-disable' recovery
option to the recovery policy pulldown list. (BZ#839732)

* Prior to this update, line breaks that were not anticipated in the
'yum list' output could cause package upgrade and/or installation to
fail when creating clusters or adding nodes to existing clusters. As a
consequence, creating clusters and adding cluster nodes to existing
clusters could fail. This update modifies the ricci daemon to be able
to correctly handle line breaks in the 'yum list' output. (BZ#842865)

In addition, this update adds the following enhancements :

* This update adds support for configuring the Intel iPDU fence agent
to the luci package. (BZ#741986)

* This update adds support for viewing and changing the state of the
new 'nfsrestart' attribute to the FS and Cluster FS resource agent
configuration screens. (BZ#822633)

All users of conga are advised to upgrade to these updated packages,
which resolve these issues and add these enhancements. After
installing this update, the luci and ricci services will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019202.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3008fba3"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-January/000323.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85d458a2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3359");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"luci-0.12.2-64.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ricci-0.12.2-64.el5.centos")) flag++;


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
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "luci / ricci");
}
