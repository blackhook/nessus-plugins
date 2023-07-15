#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:7647.
##

include('compat.inc');

if (description)
{
  script_id(167444);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/14");

  script_cve_id(
    "CVE-2022-22719",
    "CVE-2022-22721",
    "CVE-2022-23943",
    "CVE-2022-26377",
    "CVE-2022-28614",
    "CVE-2022-28615",
    "CVE-2022-29404",
    "CVE-2022-30522",
    "CVE-2022-30556",
    "CVE-2022-31813"
  );
  script_xref(name:"ALSA", value:"2022:7647");

  script_name(english:"AlmaLinux 8 : httpd:2.4 (ALSA-2022:7647)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:7647 advisory.

  - A carefully crafted request body can cause a read to a random memory area which could cause the process to
    crash. This issue affects Apache HTTP Server 2.4.52 and earlier. (CVE-2022-22719)

  - If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems
    an integer overflow happens which later causes out of bounds writes. This issue affects Apache HTTP Server
    2.4.52 and earlier. (CVE-2022-22721)

  - Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap
    memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and
    prior versions. (CVE-2022-23943)

  - Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of
    Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This
    issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.
    (CVE-2022-26377)

  - The ap_rwrite() function in Apache HTTP Server 2.4.53 and earlier may read unintended memory if an
    attacker can cause the server to reflect very large input using ap_rwrite() or ap_rputs(), such as with
    mod_luas r:puts() function. Modules compiled and distributed separately from Apache HTTP Server that use
    the 'ap_rputs' function and may pass it a very large (INT_MAX or larger) string must be compiled against
    current headers to resolve the issue. (CVE-2022-28614)

  - Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read beyond bounds in
    ap_strcmp_match() when provided with an extremely large input buffer. While no code distributed with the
    server can be coerced into such a call, third-party modules or lua scripts that use ap_strcmp_match() may
    hypothetically be affected. (CVE-2022-28615)

  - In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua script that calls r:parsebody(0)
    may cause a denial of service due to no default limit on possible input size. (CVE-2022-29404)

  - If Apache HTTP Server 2.4.53 is configured to do transformations with mod_sed in contexts where the input
    to mod_sed may be very large, mod_sed may make excessively large memory allocations and trigger an abort.
    (CVE-2022-30522)

  - Apache HTTP Server 2.4.53 and earlier may return lengths to applications calling r:wsread() that point
    past the end of the storage allocated for the buffer. (CVE-2022-30556)

  - Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on
    client side Connection header hop-by-hop mechanism. This may be used to bypass IP based authentication on
    the origin server/application. (CVE-2022-31813)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-7647.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31813");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 190, 200, 345, 348, 444, 665, 770, 787, 789, 908);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
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
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/httpd');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');
if ('2.4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module httpd:' + module_ver);

var appstreams = {
    'httpd:2.4': [
      {'reference':'httpd-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-devel-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-devel-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-filesystem-2.4.37-51.module_el8.7.0+3281+01e58653', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-manual-2.4.37-51.module_el8.7.0+3281+01e58653', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-tools-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-tools-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_http2-1.15.7-5.module_el8.6.0+2872+fe0ff7aa', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_http2-1.15.7-5.module_el8.6.0+2872+fe0ff7aa', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ldap-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ldap-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_md-2.0.8-8.module_el8.6.0+2872+fe0ff7aa', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_md-2.0.8-8.module_el8.6.0+2872+fe0ff7aa', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_session-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_session-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ssl-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_ssl-2.4.37-51.module_el8.7.0+3281+01e58653', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-devel / httpd-filesystem / httpd-manual / httpd-tools / etc');
}
