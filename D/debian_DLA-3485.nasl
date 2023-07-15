#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3485. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(178052);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/08");

  script_cve_id("CVE-2022-39369");

  script_name(english:"Debian DLA-3485-1 : php-cas - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by a vulnerability as referenced in the dla-3485
advisory.

  - phpCAS is an authentication library that allows PHP applications to easily authenticate users via a
    Central Authentication Service (CAS) server. The phpCAS library uses HTTP headers to determine the service
    URL used to validate tickets. This allows an attacker to control the host header and use a valid ticket
    granted for any authorized service in the same SSO realm (CAS server) to authenticate to the service
    protected by phpCAS. Depending on the settings of the CAS server service registry in worst case this may
    be any other service URL (if the allowed URLs are configured to ^(https)://.*) or may be strictly
    limited to known and authorized services in the same SSO federation if proper URL service validation is
    applied. This vulnerability may allow an attacker to gain access to a victim's account on a vulnerable
    CASified service without victim's knowledge, when the victim visits attacker's website while being logged
    in to the same CAS server. phpCAS 1.6.0 is a major version upgrade that starts enforcing service URL
    discovery validation, because there is unfortunately no 100% safe default config to use in PHP. Starting
    this version, it is required to pass in an additional service base URL argument when constructing the
    client class. For more information, please refer to the upgrading doc. This vulnerability only impacts the
    CAS client that the phpCAS library protects against. The problematic service URL discovery behavior in
    phpCAS < 1.6.0 will only be disabled, and thus you are not impacted from it, if the phpCAS configuration
    has the following setup: 1. `phpCAS::setUrl()` is called (a reminder that you have to pass in the full URL
    of the current page, rather than your service base URL), and 2. `phpCAS::setCallbackURL()` is called, only
    when the proxy mode is enabled. 3. If your PHP's HTTP header input `X-Forwarded-Host`, `X-Forwarded-
    Server`, `Host`, `X-Forwarded-Proto`, `X-Forwarded-Protocol` is sanitized before reaching PHP (by a
    reverse proxy, for example), you will not be impacted by this vulnerability either. If your CAS server
    service registry is configured to only allow known and trusted service URLs the severity of the
    vulnerability is reduced substantially in its severity since an attacker must be in control of another
    authorized service. Otherwise, you should upgrade the library to get the safe service discovery behavior.
    (CVE-2022-39369)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1023571");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php-cas");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3485");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39369");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/php-cas");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php-cas packages.

For Debian 10 buster, this problem has been fixed in version 1.3.6-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39369");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-cas");
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
    {'release': '10.0', 'prefix': 'php-cas', 'reference': '1.3.6-1+deb10u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-cas');
}
