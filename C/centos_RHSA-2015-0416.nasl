#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0416 and 
# CentOS Errata and Security Advisory 2015:0416 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81893);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-8105", "CVE-2014-8112");
  script_bugtraq_id(72985, 73033);
  script_xref(name:"RHSA", value:"2015:0416");

  script_name(english:"CentOS 7 : 389-ds-base (CESA-2015:0416)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated 389-ds-base packages that fix two security issues, several
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

An information disclosure flaw was found in the way the 389 Directory
Server stored information in the Changelog that is exposed via the
'cn=changelog' LDAP sub-tree. An unauthenticated user could in certain
cases use this flaw to read data from the Changelog, which could
include sensitive information such as plain-text passwords.
(CVE-2014-8105)

It was found that when the nsslapd-unhashed-pw-switch 389 Directory
Server configuration option was set to 'off', it did not prevent the
writing of unhashed passwords into the Changelog. This could
potentially allow an authenticated user able to access the Changelog
to read sensitive information. (CVE-2014-8112)

The CVE-2014-8105 issue was discovered by Petr Spacek of the Red Hat
Identity Management Engineering Team, and the CVE-2014-8112 issue was
discovered by Ludwig Krispenz of the Red Hat Identity Management
Engineering Team.

Enhancements :

* Added new WinSync configuration parameters: winSyncSubtreePair for
synchronizing multiple subtrees, as well as winSyncWindowsFilter and
winSyncDirectoryFilter for synchronizing restricted sets by filters.
(BZ# 746646)

* It is now possible to stop, start, or configure plug-ins without the
need to restart the server for the change to take effect. (BZ#994690)

* Access control related to the MODDN and MODRDN operations has been
updated: the source and destination targets can be specified in the
same access control instruction. (BZ#1118014)

* The nsDS5ReplicaBindDNGroup attribute for using a group
distinguished name in binding to replicas has been added. (BZ#1052754)

* WinSync now supports range retrieval. If more than the MaxValRange
number of attribute values exist per attribute, WinSync synchronizes
all the attributes to the directory server using the range retrieval.
(BZ#1044149)

* Support for the RFC 4527 Read Entry Controls and RFC 4533 Content
Synchronization Operation LDAP standards has been added. (BZ#1044139,
BZ# 1044159)

* The Referential Integrity (referint) plug-in can now use an
alternate configuration area. The PlugInArg plug-in configuration now
uses unique configuration attributes. Configuration changes no longer
require a server restart. (BZ#1044203)

* The logconv.pl log analysis tool now supports gzip, bzip2, and xz
compressed files and also TAR archives and compressed TAR archives of
these files. (BZ#1044188)

* Only the Directory Manager could add encoded passwords or force
users to change their password after a reset. Users defined in the
passwordAdminDN attribute can now also do this. (BZ#1118007)

* The 'nsslapd-memberofScope' configuration parameter has been added
to the MemberOf plug-in. With MemberOf enabled and a scope defined,
moving a group out of scope with a MODRDN operation failed. Moving a
member entry out of scope now correctly removes the memberof value.
(BZ#1044170)

* The alwaysRecordLoginAttr attribute has been addded to the Account
Policy plug-in configuration entry, which allows to distinguish
between an attribute for checking the activity of an account and an
attribute to be updated at successful login. (BZ#1060032)

* A root DSE search, using the ldapsearch command with the '-s base -b
''' options, returns only the user attributes instead of the
operational attributes. The 'nsslapd-return-default' option has been
added for backward compatibility. (BZ#1118021)

* The configuration of the MemberOf plug-in can be stored in a suffix
mapped to a back-end database, which allows MemberOf configuration to
be replicated. (BZ#1044205)

* Added support for the SSL versions from the range supported by the
NSS library available on the system. Due to the POODLE vulnerability,
SSLv3 is disabled by default even if NSS supports it. (BZ#1044191)"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-March/001486.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a875f30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8105");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-1.3.3.1-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.3.1-13.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.3.1-13.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs");
}
