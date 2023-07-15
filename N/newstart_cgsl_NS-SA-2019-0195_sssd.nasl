#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0195. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129890);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-16838", "CVE-2019-3811");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : sssd Multiple Vulnerabilities (NS-SA-2019-0195)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has sssd packages installed that are affected by
multiple vulnerabilities:

  - A vulnerability was found in sssd. If a user was
    configured with no home directory set, sssd would return
    '/' (the root directory) instead of '' (the empty string
    / no home directory). This could impact services that
    restrict the user's filesystem access to within their
    home directory through chroot() etc. All versions before
    2.1 are vulnerable. (CVE-2019-3811)

  - A flaw was found in sssd Group Policy Objects
    implementation. When the GPO is not readable by SSSD due
    to a too strict permission settings on the server side,
    SSSD will allow all authenticated users to login instead
    of denying access. (CVE-2018-16838)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0195");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sssd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16838");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "libipa_hbac-1.16.4-21.el7",
    "libipa_hbac-devel-1.16.4-21.el7",
    "libsss_autofs-1.16.4-21.el7",
    "libsss_certmap-1.16.4-21.el7",
    "libsss_certmap-devel-1.16.4-21.el7",
    "libsss_idmap-1.16.4-21.el7",
    "libsss_idmap-devel-1.16.4-21.el7",
    "libsss_nss_idmap-1.16.4-21.el7",
    "libsss_nss_idmap-devel-1.16.4-21.el7",
    "libsss_simpleifp-1.16.4-21.el7",
    "libsss_simpleifp-devel-1.16.4-21.el7",
    "libsss_sudo-1.16.4-21.el7",
    "python-libipa_hbac-1.16.4-21.el7",
    "python-libsss_nss_idmap-1.16.4-21.el7",
    "python-sss-1.16.4-21.el7",
    "python-sss-murmur-1.16.4-21.el7",
    "python-sssdconfig-1.16.4-21.el7",
    "sssd-1.16.4-21.el7",
    "sssd-ad-1.16.4-21.el7",
    "sssd-client-1.16.4-21.el7",
    "sssd-common-1.16.4-21.el7",
    "sssd-common-pac-1.16.4-21.el7",
    "sssd-dbus-1.16.4-21.el7",
    "sssd-debuginfo-1.16.4-21.el7",
    "sssd-ipa-1.16.4-21.el7",
    "sssd-kcm-1.16.4-21.el7",
    "sssd-krb5-1.16.4-21.el7",
    "sssd-krb5-common-1.16.4-21.el7",
    "sssd-ldap-1.16.4-21.el7",
    "sssd-libwbclient-1.16.4-21.el7",
    "sssd-libwbclient-devel-1.16.4-21.el7",
    "sssd-polkit-rules-1.16.4-21.el7",
    "sssd-proxy-1.16.4-21.el7",
    "sssd-tools-1.16.4-21.el7",
    "sssd-winbind-idmap-1.16.4-21.el7"
  ],
  "CGSL MAIN 5.04": [
    "libipa_hbac-1.16.4-21.el7",
    "libipa_hbac-devel-1.16.4-21.el7",
    "libsss_autofs-1.16.4-21.el7",
    "libsss_certmap-1.16.4-21.el7",
    "libsss_certmap-devel-1.16.4-21.el7",
    "libsss_idmap-1.16.4-21.el7",
    "libsss_idmap-devel-1.16.4-21.el7",
    "libsss_nss_idmap-1.16.4-21.el7",
    "libsss_nss_idmap-devel-1.16.4-21.el7",
    "libsss_simpleifp-1.16.4-21.el7",
    "libsss_simpleifp-devel-1.16.4-21.el7",
    "libsss_sudo-1.16.4-21.el7",
    "python-libipa_hbac-1.16.4-21.el7",
    "python-libsss_nss_idmap-1.16.4-21.el7",
    "python-sss-1.16.4-21.el7",
    "python-sss-murmur-1.16.4-21.el7",
    "python-sssdconfig-1.16.4-21.el7",
    "sssd-1.16.4-21.el7",
    "sssd-ad-1.16.4-21.el7",
    "sssd-client-1.16.4-21.el7",
    "sssd-common-1.16.4-21.el7",
    "sssd-common-pac-1.16.4-21.el7",
    "sssd-dbus-1.16.4-21.el7",
    "sssd-debuginfo-1.16.4-21.el7",
    "sssd-ipa-1.16.4-21.el7",
    "sssd-kcm-1.16.4-21.el7",
    "sssd-krb5-1.16.4-21.el7",
    "sssd-krb5-common-1.16.4-21.el7",
    "sssd-ldap-1.16.4-21.el7",
    "sssd-libwbclient-1.16.4-21.el7",
    "sssd-libwbclient-devel-1.16.4-21.el7",
    "sssd-polkit-rules-1.16.4-21.el7",
    "sssd-proxy-1.16.4-21.el7",
    "sssd-tools-1.16.4-21.el7",
    "sssd-winbind-idmap-1.16.4-21.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}