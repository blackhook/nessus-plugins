#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3409. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174970);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id(
    "CVE-2019-20479",
    "CVE-2021-32785",
    "CVE-2021-32786",
    "CVE-2021-32791",
    "CVE-2021-32792",
    "CVE-2023-28625"
  );

  script_name(english:"Debian DLA-3409-1 : libapache2-mod-auth-openidc - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3409 advisory.

  - A flaw was found in mod_auth_openidc before version 2.4.1. An open redirect issue exists in URLs with a
    slash and backslash at the beginning. (CVE-2019-20479)

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

  - mod_auth_openidc is an authentication and authorization module for the Apache 2.x HTTP server that
    implements the OpenID Connect Relying Party functionality. In versions 2.0.0 through 2.4.13.1, when
    `OIDCStripCookies` is set and a crafted cookie supplied, a NULL pointer dereference would occur, resulting
    in a segmentation fault. This could be used in a Denial-of-Service attack and thus presents an
    availability risk. Version 2.4.13.2 contains a patch for this issue. As a workaround, avoid using
    `OIDCStripCookies`. (CVE-2023-28625)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/libapache2-mod-auth-openidc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0371ebc9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libapache2-mod-auth-openidc packages.

For Debian 10 buster, these problems have been fixed in version 2.3.10.2-1+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32786");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-32792");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-auth-openidc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libapache2-mod-auth-openidc', 'reference': '2.3.10.2-1+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libapache2-mod-auth-openidc');
}
