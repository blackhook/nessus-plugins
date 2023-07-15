##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:1823.
##

include('compat.inc');

if (description)
{
  script_id(161141);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2021-32786",
    "CVE-2021-32791",
    "CVE-2021-32792",
    "CVE-2021-39191"
  );
  script_xref(name:"ALSA", value:"2022:1823");

  script_name(english:"AlmaLinux 8 : mod_auth_openidc:2.3 (ALSA-2022:1823)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:1823 advisory.

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

  - mod_auth_openidc is an authentication/authorization module for the Apache 2.x HTTP server that functions
    as an OpenID Connect Relying Party, authenticating users against an OpenID Connect Provider. In versions
    prior to 2.4.9.4, the 3rd-party init SSO functionality of mod_auth_openidc was reported to be vulnerable
    to an open redirect attack by supplying a crafted URL in the `target_link_uri` parameter. A patch in
    version 2.4.9.4 made it so that the `OIDCRedirectURLsAllowed` setting must be applied to the
    `target_link_uri` parameter. There are no known workarounds aside from upgrading to a patched version.
    (CVE-2021-39191)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-1823.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected cjose, cjose-devel and / or mod_auth_openidc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39191");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:cjose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:cjose-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_auth_openidc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/mod_auth_openidc');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mod_auth_openidc:2.3');
if ('2.3' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mod_auth_openidc:' + module_ver);

var appstreams = {
    'mod_auth_openidc:2.3': [
      {'reference':'cjose-0.6.1-2.module_el8.6.0+2868+44838709', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cjose-0.6.1-2.module_el8.6.0+2868+44838709', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cjose-devel-0.6.1-2.module_el8.6.0+2868+44838709', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cjose-devel-0.6.1-2.module_el8.6.0+2868+44838709', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_auth_openidc-2.3.7-11.module_el8.6.0+2868+44838709', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_auth_openidc-2.3.7-11.module_el8.6.0+2868+44838709', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mod_auth_openidc:2.3');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cjose / cjose-devel / mod_auth_openidc');
}
