##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-4751.
##

include('compat.inc');

if (description)
{
  script_id(142762);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-17189",
    "CVE-2019-0196",
    "CVE-2019-0197",
    "CVE-2019-10081",
    "CVE-2019-10082",
    "CVE-2019-10092",
    "CVE-2019-10097",
    "CVE-2019-10098",
    "CVE-2020-1927",
    "CVE-2020-1934"
  );
  script_bugtraq_id(106685, 107665, 107669);
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"Oracle Linux 8 : httpd:2.4 (ELSA-2020-4751)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-4751 advisory.

  - A vulnerability was found in Apache HTTP Server 2.4.17 to 2.4.38. Using fuzzed network input, the http/2
    request handling could be made to access freed memory in string comparison when determining the method of
    a request and thus process the request incorrectly. (CVE-2019-0196)

  - In Apache HTTP server versions 2.4.37 and prior, by sending request bodies in a slow loris way to plain
    resources, the h2 stream for that request unnecessarily occupied a server thread cleaning up that incoming
    data. This affects only HTTP/2 (mod_http2) connections. (CVE-2018-17189)

  - A vulnerability was found in Apache HTTP Server 2.4.34 to 2.4.38. When HTTP/2 was enabled for a http: host
    or H2Upgrade was enabled for h2 on a https: host, an Upgrade request from http/1.1 to http/2 that was not
    the first request on a connection could lead to a misconfiguration and crash. Server that never enabled
    the h2 protocol or that only enabled it for https: and did not set H2Upgrade on are unaffected by this
    issue. (CVE-2019-0197)

  - HTTP/2 (2.4.20 through 2.4.39) very early pushes, for example configured with H2PushResource, could lead
    to an overwrite of memory in the pushing request's pool, leading to crashes. The memory copied is that of
    the configured push link header values, not data supplied by the client. (CVE-2019-10081)

  - In Apache HTTP Server 2.4.18-2.4.39, using fuzzed network input, the http/2 session handling could be made
    to read memory after being freed, during connection shutdown. (CVE-2019-10082)

  - In Apache HTTP Server 2.4.0-2.4.39, a limited cross-site scripting issue was reported affecting the
    mod_proxy error page. An attacker could cause the link on the error page to be malformed and instead point
    to a page of their choice. This would only be exploitable where a server was set up with proxying enabled
    but was misconfigured in such a way that the Proxy Error page was displayed. (CVE-2019-10092)

  - In Apache HTTP Server 2.4.32-2.4.39, when mod_remoteip was configured to use a trusted intermediary proxy
    server using the PROXY protocol, a specially crafted PROXY header could trigger a stack buffer overflow
    or NULL pointer deference. This vulnerability could only be triggered by a trusted proxy and not by
    untrusted HTTP clients. (CVE-2019-10097)

  - In Apache HTTP Server 2.4.0 to 2.4.41, redirects configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and redirect instead to an an unexpected URL within
    the request URL. (CVE-2020-1927)

  - In Apache HTTP server 2.4.0 to 2.4.39, Redirects configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and redirect instead to an unexpected URL within the
    request URL. (CVE-2019-10098)

  - In Apache HTTP Server 2.4.0 to 2.4.41, mod_proxy_ftp may use uninitialized memory when proxying to a
    malicious FTP server. (CVE-2020-1934)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-4751.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

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

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'httpd-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-devel-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-devel-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-filesystem-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-manual-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-tools-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'httpd-tools-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_http2-1.15.7-2.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_http2-1.15.7-2.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ldap-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ldap-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_md-2.0.8-8.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_md-2.0.8-8.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_proxy_html-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_session-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_session-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mod_ssl-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'mod_ssl-2.4.37-30.0.1.module+el8.3.0+7816+49791cfd', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_WARNING,
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
