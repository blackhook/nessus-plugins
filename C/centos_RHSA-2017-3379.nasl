#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3379 and 
# CentOS Errata and Security Advisory 2017:3379 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105059);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-12173");
  script_xref(name:"RHSA", value:"2017:3379");

  script_name(english:"CentOS 7 : sssd (CESA-2017:3379)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for sssd is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The System Security Services Daemon (SSSD) service provides a set of
daemons to manage access to remote directories and authentication
mechanisms. It also provides the Name Service Switch (NSS) and the
Pluggable Authentication Modules (PAM) interfaces toward the system,
and a pluggable back-end system to connect to multiple different
account sources.

Security Fix(es) :

* It was found that sssd's sysdb_search_user_by_upn_res() function did
not sanitize requests when querying its local cache and was vulnerable
to injection. In a centralized login environment, if a password hash
was locally cached for a given user, an authenticated attacker could
use this flaw to retrieve it. (CVE-2017-12173)

This issue was discovered by Sumit Bose (Red Hat).

Bug Fix(es) :

* Previously, SSSD's krb5 provider did not respect changed UIDs in ID
views overriding the default view. Consequently, Kerberos credential
caches were created with the incorrect, original UID, and processes of
the user were not able to find the changed UID. With this update,
SSSD's krb5 provider is made aware of the proper ID view name and
respects the ID override data. As a result, the Kerberos credential
cache is now created with the expected UID, and the processes can find
it. (BZ#1508972)

* Previously, the list of cache request domains was sometimes freed in
the middle of a cache request operation due to the refresh domains
request, as they both were using the same list. As a consequence, a
segmentation fault sometimes occurred in SSSD. With this update, SSSD
uses a copy of the cache request domains' list for each cache request.
As a result, SSSD no longer crashes in this case. (BZ#1509177)

* Previously, the calls provided by SSSD to send data to the Privilege
Attribute Certificate (PAC) responder did not use a mutex or any other
means to serialize access to the PAC responder from a single process.
When multithreaded applications overran the PAC responder with
multiple parallel requests, some threads did not receive a proper
reply. Consequently, such threads only resumed work after waiting 5
minutes for a response. This update configures mutex to serialize
access to the PAC responder socket for multithreaded applications. As
a result, all threads now get a proper and timely reply. (BZ#1506682)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-December/022685.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7ce01c6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12173");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libipa_hbac-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libipa_hbac-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_autofs-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_certmap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_certmap-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_idmap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_idmap-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_nss_idmap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_nss_idmap-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_simpleifp-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_simpleifp-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsss_sudo-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-libipa_hbac-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-libsss_nss_idmap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-sss-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-sss-murmur-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-sssdconfig-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-ad-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-client-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-common-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-common-pac-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-dbus-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-ipa-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-kcm-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-krb5-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-krb5-common-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-ldap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-libwbclient-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-libwbclient-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-polkit-rules-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-proxy-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-tools-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sssd-winbind-idmap-1.15.2-50.el7_4.8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libsss_autofs / libsss_certmap / etc");
}
