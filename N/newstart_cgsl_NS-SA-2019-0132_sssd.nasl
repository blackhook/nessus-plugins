#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0132. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127388);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-12173");

  script_name(english:"NewStart CGSL MAIN 4.05 : sssd Vulnerability (NS-SA-2019-0132)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has sssd packages installed that are affected by a
vulnerability:

  - It was found that sssd's sysdb_search_user_by_upn_res()
    function did not sanitize requests when querying its
    local cache and was vulnerable to injection. In a
    centralized login environment, if a password hash was
    locally cached for a given user, an authenticated
    attacker could use this flaw to retrieve it.
    (CVE-2017-12173)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0132");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL sssd packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/27");
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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "libipa_hbac-1.13.3-60.el6",
    "libipa_hbac-devel-1.13.3-60.el6",
    "libsss_idmap-1.13.3-60.el6",
    "libsss_idmap-devel-1.13.3-60.el6",
    "libsss_nss_idmap-1.13.3-60.el6",
    "libsss_nss_idmap-devel-1.13.3-60.el6",
    "libsss_simpleifp-1.13.3-60.el6",
    "libsss_simpleifp-devel-1.13.3-60.el6",
    "python-libipa_hbac-1.13.3-60.el6",
    "python-libsss_nss_idmap-1.13.3-60.el6",
    "python-sss-1.13.3-60.el6",
    "python-sss-murmur-1.13.3-60.el6",
    "python-sssdconfig-1.13.3-60.el6",
    "sssd-1.13.3-60.el6",
    "sssd-ad-1.13.3-60.el6",
    "sssd-client-1.13.3-60.el6",
    "sssd-common-1.13.3-60.el6",
    "sssd-common-pac-1.13.3-60.el6",
    "sssd-dbus-1.13.3-60.el6",
    "sssd-debuginfo-1.13.3-60.el6",
    "sssd-ipa-1.13.3-60.el6",
    "sssd-krb5-1.13.3-60.el6",
    "sssd-krb5-common-1.13.3-60.el6",
    "sssd-ldap-1.13.3-60.el6",
    "sssd-proxy-1.13.3-60.el6",
    "sssd-tools-1.13.3-60.el6"
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
