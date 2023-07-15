#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-1995.
##

include('compat.inc');

if (description)
{
  script_id(173238);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2022-4254");

  script_name(english:"Amazon Linux 2 : sssd (ALAS-2023-1995)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of sssd installed on the remote host is prior to 1.16.5-10. It is, therefore, affected by a vulnerability as
referenced in the ALAS2-2023-1995 advisory.

  - sssd: libsss_certmap fails to sanitise certificate data used in LDAP filters (CVE-2022-4254)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-1995.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4254.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update sssd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4254");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'libipa_hbac-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libipa_hbac-devel-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_autofs-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_certmap-devel-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_idmap-devel-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_nss_idmap-devel-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_simpleifp-devel-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsss_sudo-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libipa_hbac-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libipa_hbac-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libipa_hbac-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libsss_nss_idmap-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libsss_nss_idmap-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-libsss_nss_idmap-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-murmur-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-murmur-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sss-murmur-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-sssdconfig-1.16.5-10.amzn2.15', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ad-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-client-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-common-pac-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-dbus-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debuginfo-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debuginfo-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-debuginfo-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ipa-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-kcm-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-krb5-common-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-ldap-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-libwbclient-devel-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-polkit-rules-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-polkit-rules-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-polkit-rules-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-proxy-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-tools-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-1.16.5-10.amzn2.15', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-1.16.5-10.amzn2.15', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sssd-winbind-idmap-1.16.5-10.amzn2.15', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libsss_autofs / etc");
}