#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3020-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153244);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/14");

  script_cve_id(
    "CVE-2021-32785",
    "CVE-2021-32786",
    "CVE-2021-32791",
    "CVE-2021-32792"
  );

  script_name(english:"openSUSE 15 Security Update : apache2-mod_auth_openidc (openSUSE-SU-2021:3020-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3020-1 advisory.

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. When
    mod_auth_openidc versions prior to 2.4.9 are configured to use an unencrypted Redis cache
    (`OIDCCacheEncrypt off`, `OIDCSessionType server-cache`, `OIDCCacheType redis`), `mod_auth_openidc`
    wrongly performed argument interpolation before passing Redis requests to `hiredis`, which would perform
    it again and lead to an uncontrolled format string bug. Initial assessment shows that this bug does not
    appear to allow gaining arbitrary code execution, but can reliably provoke a denial of service by
    repeatedly crashing the Apache workers. This bug has been corrected in version 2.4.9 by performing
    argument interpolation only once, using the `hiredis` API. As a workaround, this vulnerability can be
    mitigated by setting `OIDCCacheEncrypt` to `on`, as cache keys are cryptographically hashed before use
    when this option is enabled. (CVE-2021-32785)

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. In versions
    prior to 2.4.9, `oidc_validate_redirect_url()` does not parse URLs the same way as most browsers do. As a
    result, this function can be bypassed and leads to an Open Redirect vulnerability in the logout
    functionality. This bug has been fixed in version 2.4.9 by replacing any backslash of the URL to redirect
    with slashes to address a particular breaking change between the different specifications (RFC2396 /
    RFC3986 and WHATWG). As a workaround, this vulnerability can be mitigated by configuring
    `mod_auth_openidc` to only allow redirection whose destination matches a given regular expression.
    (CVE-2021-32786)

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. In
    mod_auth_openidc before version 2.4.9, the AES GCM encryption in mod_auth_openidc uses a static IV and
    AAD. It is important to fix because this creates a static nonce and since aes-gcm is a stream cipher, this
    can lead to known cryptographic issues, since the same key is being reused. From 2.4.9 onwards this has
    been patched to use dynamic values through usage of cjose AES encryption routines. (CVE-2021-32791)

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. In
    mod_auth_openidc before version 2.4.9, there is an XSS vulnerability in when using `OIDCPreservePost On`.
    (CVE-2021-32792)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188849");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/54B4RYNP5L63X2FMX2QCVYB2LGLL42IY/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c72508c7");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32792");
  script_set_attribute(attribute:"solution", value:
"Update the affected apache2-mod_auth_openidc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_auth_openidc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'apache2-mod_auth_openidc-2.3.8-3.15.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_auth_openidc');
}
