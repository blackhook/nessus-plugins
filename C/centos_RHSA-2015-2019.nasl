#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2019 and 
# CentOS Errata and Security Advisory 2015:2019 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86831);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-5292");
  script_xref(name:"RHSA", value:"2015:2019");

  script_name(english:"CentOS 6 : sssd (CESA-2015:2019)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The System Security Services Daemon (SSSD) service provides a set of
daemons to manage access to remote directories and authentication
mechanisms. It also provides the Name Service Switch (NSS) and the
Pluggable Authentication Modules (PAM) interfaces toward the system,
and a pluggable back-end system to connect to multiple different
account sources.

It was found that SSSD's Privilege Attribute Certificate (PAC)
responder plug-in would leak a small amount of memory on each
authentication request. A remote attacker could potentially use this
flaw to exhaust all available memory on the system by making repeated
requests to a Kerberized daemon application configured to authenticate
using the PAC responder plug-in. (CVE-2015-5292)

This update also fixes the following bugs :

* Previously, SSSD did not correctly handle sudo rules that applied to
groups with names containing special characters, such as the '('
opening parenthesis sign. Consequently, SSSD skipped such sudo rules.
The internal sysdb search has been modified to escape special
characters when searching for objects to which sudo rules apply. As a
result, SSSD applies the described sudo rules as expected.
(BZ#1258398)

* Prior to this update, SSSD did not correctly handle group names
containing special Lightweight Directory Access Protocol (LDAP)
characters, such as the '(' or ')' parenthesis signs. When a group
name contained one or more such characters, the internal cache cleanup
operation failed with an I/O error. With this update, LDAP special
characters in the Distinguished Name (DN) of a cache entry are escaped
before the cleanup operation starts. As a result, the cleanup
operation completes successfully in the described situation.
(BZ#1264098)

* Applications performing Kerberos authentication previously increased
the memory footprint of the Kerberos plug-in that parses the Privilege
Attribute Certificate (PAC) information. The plug-in has been updated
to free the memory it allocates, thus fixing this bug. (BZ#1268783)

* Previously, when malformed POSIX attributes were defined in an
Active Directory (AD) LDAP server, SSSD unexpectedly switched to
offline mode. This update relaxes certain checks for AD POSIX
attribute validity. As a result, SSSD now works as expected even when
malformed POSIX attributes are present in AD and no longer enters
offline mode in the described situation. (BZ#1268784)

All sssd users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the update, the sssd service will be restarted automatically.
Additionally, all running applications using the PAC responder plug-in
must be restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-November/021498.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14f87ae3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5292");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-devel-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libipa_hbac-python-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_idmap-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_idmap-devel-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_nss_idmap-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_nss_idmap-devel-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_nss_idmap-python-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_simpleifp-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libsss_simpleifp-devel-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-sssdconfig-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-ad-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-client-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-common-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-common-pac-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-dbus-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-ipa-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-krb5-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-krb5-common-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-ldap-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-proxy-1.12.4-47.el6_7.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"sssd-tools-1.12.4-47.el6_7.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libipa_hbac-python / libsss_idmap / etc");
}
