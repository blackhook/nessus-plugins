#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0067. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127267);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2018-10852");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : sssd Vulnerability (NS-SA-2019-0067)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has sssd packages installed that are affected by a
vulnerability:

  - The UNIX pipe which sudo uses to contact SSSD and read
    the available sudo rules from SSSD utilizes too broad of
    a set of permissions. Any user who can send a message
    using the same raw protocol that sudo and SSSD use can
    read the sudo rules available for any user.
    (CVE-2018-10852)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0067");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sssd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10852");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

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
    "libipa_hbac-1.16.2-13.el7_6.5",
    "libipa_hbac-devel-1.16.2-13.el7_6.5",
    "libsss_autofs-1.16.2-13.el7_6.5",
    "libsss_certmap-1.16.2-13.el7_6.5",
    "libsss_certmap-devel-1.16.2-13.el7_6.5",
    "libsss_idmap-1.16.2-13.el7_6.5",
    "libsss_idmap-devel-1.16.2-13.el7_6.5",
    "libsss_nss_idmap-1.16.2-13.el7_6.5",
    "libsss_nss_idmap-devel-1.16.2-13.el7_6.5",
    "libsss_simpleifp-1.16.2-13.el7_6.5",
    "libsss_simpleifp-devel-1.16.2-13.el7_6.5",
    "libsss_sudo-1.16.2-13.el7_6.5",
    "python-libipa_hbac-1.16.2-13.el7_6.5",
    "python-libsss_nss_idmap-1.16.2-13.el7_6.5",
    "python-sss-1.16.2-13.el7_6.5",
    "python-sss-murmur-1.16.2-13.el7_6.5",
    "python-sssdconfig-1.16.2-13.el7_6.5",
    "sssd-1.16.2-13.el7_6.5",
    "sssd-ad-1.16.2-13.el7_6.5",
    "sssd-client-1.16.2-13.el7_6.5",
    "sssd-common-1.16.2-13.el7_6.5",
    "sssd-common-pac-1.16.2-13.el7_6.5",
    "sssd-dbus-1.16.2-13.el7_6.5",
    "sssd-debuginfo-1.16.2-13.el7_6.5",
    "sssd-ipa-1.16.2-13.el7_6.5",
    "sssd-kcm-1.16.2-13.el7_6.5",
    "sssd-krb5-1.16.2-13.el7_6.5",
    "sssd-krb5-common-1.16.2-13.el7_6.5",
    "sssd-ldap-1.16.2-13.el7_6.5",
    "sssd-libwbclient-1.16.2-13.el7_6.5",
    "sssd-libwbclient-devel-1.16.2-13.el7_6.5",
    "sssd-polkit-rules-1.16.2-13.el7_6.5",
    "sssd-proxy-1.16.2-13.el7_6.5",
    "sssd-tools-1.16.2-13.el7_6.5",
    "sssd-winbind-idmap-1.16.2-13.el7_6.5"
  ],
  "CGSL MAIN 5.04": [
    "libipa_hbac-1.16.2-13.el7_6.5",
    "libipa_hbac-devel-1.16.2-13.el7_6.5",
    "libsss_autofs-1.16.2-13.el7_6.5",
    "libsss_certmap-1.16.2-13.el7_6.5",
    "libsss_certmap-devel-1.16.2-13.el7_6.5",
    "libsss_idmap-1.16.2-13.el7_6.5",
    "libsss_idmap-devel-1.16.2-13.el7_6.5",
    "libsss_nss_idmap-1.16.2-13.el7_6.5",
    "libsss_nss_idmap-devel-1.16.2-13.el7_6.5",
    "libsss_simpleifp-1.16.2-13.el7_6.5",
    "libsss_simpleifp-devel-1.16.2-13.el7_6.5",
    "libsss_sudo-1.16.2-13.el7_6.5",
    "python-libipa_hbac-1.16.2-13.el7_6.5",
    "python-libsss_nss_idmap-1.16.2-13.el7_6.5",
    "python-sss-1.16.2-13.el7_6.5",
    "python-sss-murmur-1.16.2-13.el7_6.5",
    "python-sssdconfig-1.16.2-13.el7_6.5",
    "sssd-1.16.2-13.el7_6.5",
    "sssd-ad-1.16.2-13.el7_6.5",
    "sssd-client-1.16.2-13.el7_6.5",
    "sssd-common-1.16.2-13.el7_6.5",
    "sssd-common-pac-1.16.2-13.el7_6.5",
    "sssd-dbus-1.16.2-13.el7_6.5",
    "sssd-debuginfo-1.16.2-13.el7_6.5",
    "sssd-ipa-1.16.2-13.el7_6.5",
    "sssd-kcm-1.16.2-13.el7_6.5",
    "sssd-krb5-1.16.2-13.el7_6.5",
    "sssd-krb5-common-1.16.2-13.el7_6.5",
    "sssd-ldap-1.16.2-13.el7_6.5",
    "sssd-libwbclient-1.16.2-13.el7_6.5",
    "sssd-libwbclient-devel-1.16.2-13.el7_6.5",
    "sssd-polkit-rules-1.16.2-13.el7_6.5",
    "sssd-proxy-1.16.2-13.el7_6.5",
    "sssd-tools-1.16.2-13.el7_6.5",
    "sssd-winbind-idmap-1.16.2-13.el7_6.5"
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
