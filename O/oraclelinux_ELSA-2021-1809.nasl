#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-1809.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149913);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-17199", "CVE-2020-11984", "CVE-2020-11993");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Linux 8 : httpd:2.4 (ELSA-2021-1809)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-1809 advisory.

  - In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the session expiry time before
    decoding the session. This causes session expiry time to be ignored for mod_session_cookie sessions since
    the expiry time is loaded when the session is decoded. (CVE-2018-17199)

  - Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE (CVE-2020-11984)

  - Apache HTTP Server versions 2.4.20 to 2.4.43 When trace/debug was enabled for the HTTP/2 module and on
    certain traffic edge patterns, logging statements were made on the wrong connection, causing concurrent
    use of memory pools. Configuring the LogLevel of mod_http2 above info will mitigate this vulnerability
    for unpatched servers. (CVE-2020-11993)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-1809.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11984");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_http2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

module_ver = get_kb_item('Host/RedHat/appstream/httpd');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module httpd:2.4');
if ('2.4' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module httpd:' + module_ver);

appstreams = {
    'httpd:2.4': [
      {'reference':'httpd-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-devel-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-devel-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-filesystem-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-manual-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-tools-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-tools-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_http2-1.15.7-3.module+el8.4.0+20024+b87b2deb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_http2-1.15.7-3.module+el8.4.0+20024+b87b2deb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ldap-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ldap-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_md-2.0.8-8.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_md-2.0.8-8.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_session-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_session-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ssl-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_ssl-2.4.37-39.0.1.module+el8.4.0+20024+b87b2deb', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  appstream = NULL;
  appstream_name = NULL;
  appstream_version = NULL;
  appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      reference = NULL;
      release = NULL;
      sp = NULL;
      cpu = NULL;
      el_string = NULL;
      rpm_spec_vers_cmp = NULL;
      epoch = NULL;
      allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && release) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'httpd / httpd-devel / httpd-filesystem / etc');
}
