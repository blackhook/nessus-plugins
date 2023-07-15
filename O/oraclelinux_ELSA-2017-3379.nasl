#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:3379 and 
# Oracle Linux Security Advisory ELSA-2017-3379 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105016);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-12173");
  script_xref(name:"RHSA", value:"2017:3379");

  script_name(english:"Oracle Linux 7 : sssd (ELSA-2017-3379)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:3379 :

An update for sssd is now available for Red Hat Enterprise Linux 7.

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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-December/007396.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libipa_hbac-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libipa_hbac-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_autofs-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_certmap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_certmap-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_idmap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_idmap-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_nss_idmap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_nss_idmap-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_simpleifp-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_simpleifp-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libsss_sudo-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-libipa_hbac-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-libsss_nss_idmap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-sss-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-sss-murmur-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-sssdconfig-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-ad-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-client-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-common-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-common-pac-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-dbus-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-ipa-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-kcm-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-krb5-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-krb5-common-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-ldap-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-libwbclient-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-libwbclient-devel-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-polkit-rules-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-proxy-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-tools-1.15.2-50.el7_4.8")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"sssd-winbind-idmap-1.15.2-50.el7_4.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libsss_autofs / libsss_certmap / etc");
}
