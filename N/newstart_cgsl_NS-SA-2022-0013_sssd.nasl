##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0013. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160759);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-3621");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : sssd Vulnerability (NS-SA-2022-0013)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has sssd packages installed that are affected by a
vulnerability:

  - A flaw was found in SSSD, where the sssctl command was vulnerable to shell command injection via the logs-
    fetch and cache-expire subcommands. This flaw allows an attacker to trick the root user into running a
    specially crafted sssctl command, such as via sudo, to gain root access. The highest threat from this
    vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-3621)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0013");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3621");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sssd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'libipa_hbac-1.16.5-10.el7_9.10',
    'libipa_hbac-devel-1.16.5-10.el7_9.10',
    'libsss_autofs-1.16.5-10.el7_9.10',
    'libsss_certmap-1.16.5-10.el7_9.10',
    'libsss_certmap-devel-1.16.5-10.el7_9.10',
    'libsss_idmap-1.16.5-10.el7_9.10',
    'libsss_idmap-devel-1.16.5-10.el7_9.10',
    'libsss_nss_idmap-1.16.5-10.el7_9.10',
    'libsss_nss_idmap-devel-1.16.5-10.el7_9.10',
    'libsss_simpleifp-1.16.5-10.el7_9.10',
    'libsss_simpleifp-devel-1.16.5-10.el7_9.10',
    'libsss_sudo-1.16.5-10.el7_9.10',
    'python-libipa_hbac-1.16.5-10.el7_9.10',
    'python-libsss_nss_idmap-1.16.5-10.el7_9.10',
    'python-sss-1.16.5-10.el7_9.10',
    'python-sss-murmur-1.16.5-10.el7_9.10',
    'python-sssdconfig-1.16.5-10.el7_9.10',
    'sssd-1.16.5-10.el7_9.10',
    'sssd-ad-1.16.5-10.el7_9.10',
    'sssd-client-1.16.5-10.el7_9.10',
    'sssd-common-1.16.5-10.el7_9.10',
    'sssd-common-pac-1.16.5-10.el7_9.10',
    'sssd-dbus-1.16.5-10.el7_9.10',
    'sssd-debuginfo-1.16.5-10.el7_9.10',
    'sssd-ipa-1.16.5-10.el7_9.10',
    'sssd-kcm-1.16.5-10.el7_9.10',
    'sssd-krb5-1.16.5-10.el7_9.10',
    'sssd-krb5-common-1.16.5-10.el7_9.10',
    'sssd-ldap-1.16.5-10.el7_9.10',
    'sssd-libwbclient-1.16.5-10.el7_9.10',
    'sssd-libwbclient-devel-1.16.5-10.el7_9.10',
    'sssd-polkit-rules-1.16.5-10.el7_9.10',
    'sssd-proxy-1.16.5-10.el7_9.10',
    'sssd-tools-1.16.5-10.el7_9.10',
    'sssd-winbind-idmap-1.16.5-10.el7_9.10'
  ],
  'CGSL MAIN 5.04': [
    'libipa_hbac-1.16.5-10.el7_9.10',
    'libipa_hbac-devel-1.16.5-10.el7_9.10',
    'libsss_autofs-1.16.5-10.el7_9.10',
    'libsss_certmap-1.16.5-10.el7_9.10',
    'libsss_certmap-devel-1.16.5-10.el7_9.10',
    'libsss_idmap-1.16.5-10.el7_9.10',
    'libsss_idmap-devel-1.16.5-10.el7_9.10',
    'libsss_nss_idmap-1.16.5-10.el7_9.10',
    'libsss_nss_idmap-devel-1.16.5-10.el7_9.10',
    'libsss_simpleifp-1.16.5-10.el7_9.10',
    'libsss_simpleifp-devel-1.16.5-10.el7_9.10',
    'libsss_sudo-1.16.5-10.el7_9.10',
    'python-libipa_hbac-1.16.5-10.el7_9.10',
    'python-libsss_nss_idmap-1.16.5-10.el7_9.10',
    'python-sss-1.16.5-10.el7_9.10',
    'python-sss-murmur-1.16.5-10.el7_9.10',
    'python-sssdconfig-1.16.5-10.el7_9.10',
    'sssd-1.16.5-10.el7_9.10',
    'sssd-ad-1.16.5-10.el7_9.10',
    'sssd-client-1.16.5-10.el7_9.10',
    'sssd-common-1.16.5-10.el7_9.10',
    'sssd-common-pac-1.16.5-10.el7_9.10',
    'sssd-dbus-1.16.5-10.el7_9.10',
    'sssd-debuginfo-1.16.5-10.el7_9.10',
    'sssd-ipa-1.16.5-10.el7_9.10',
    'sssd-kcm-1.16.5-10.el7_9.10',
    'sssd-krb5-1.16.5-10.el7_9.10',
    'sssd-krb5-common-1.16.5-10.el7_9.10',
    'sssd-ldap-1.16.5-10.el7_9.10',
    'sssd-libwbclient-1.16.5-10.el7_9.10',
    'sssd-libwbclient-devel-1.16.5-10.el7_9.10',
    'sssd-polkit-rules-1.16.5-10.el7_9.10',
    'sssd-proxy-1.16.5-10.el7_9.10',
    'sssd-tools-1.16.5-10.el7_9.10',
    'sssd-winbind-idmap-1.16.5-10.el7_9.10'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sssd');
}
