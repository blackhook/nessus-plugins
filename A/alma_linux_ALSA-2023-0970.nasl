#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:0970.
##

include('compat.inc');

if (description)
{
  script_id(171990);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/28");

  script_cve_id("CVE-2006-20001", "CVE-2022-36760", "CVE-2022-37436");
  script_xref(name:"ALSA", value:"2023:0970");

  script_name(english:"AlmaLinux 9 : httpd (ALSA-2023:0970)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:0970 advisory.

  - A carefully crafted If: request header can cause a memory read, or write of a single zero byte, in a pool
    (heap) memory location beyond the header value sent. This could cause the process to crash. This issue
    affects Apache HTTP Server 2.4.54 and earlier. (CVE-2006-20001)

  - Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of
    Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This
    issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.54 and prior versions.
    (CVE-2022-36760)

  - Prior to Apache HTTP Server 2.4.55, a malicious backend can cause the response headers to be truncated
    early, resulting in some headers being incorporated into the response body. If the later headers have any
    security purpose, they will not be interpreted by the client. (CVE-2022-37436)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2023-0970.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(113, 125, 444, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'httpd-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-core-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-core-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-filesystem-2.4.53-7.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-manual-2.4.53-7.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_lua-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_lua-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_proxy_html-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mod_proxy_html-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mod_session-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-2.4.53-7.el9_1.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'mod_ssl-2.4.53-7.el9_1.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-core / httpd-devel / httpd-filesystem / httpd-manual / etc');
}
