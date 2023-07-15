##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1490.
##

include('compat.inc');

if (description)
{
  script_id(143158);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-9490", "CVE-2020-11984", "CVE-2020-11993");
  script_xref(name:"ALAS", value:"2020-1490");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Amazon Linux 2 : httpd (ALAS-2020-1490)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1490 advisory.

  - Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and possible RCE (CVE-2020-11984)

  - Apache HTTP Server versions 2.4.20 to 2.4.43 When trace/debug was enabled for the HTTP/2 module and on
    certain traffic edge patterns, logging statements were made on the wrong connection, causing concurrent
    use of memory pools. Configuring the LogLevel of mod_http2 above info will mitigate this vulnerability
    for unpatched servers. (CVE-2020-11993)

  - Apache HTTP Server versions 2.4.20 to 2.4.43. A specially crafted value for the 'Cache-Digest' header in a
    HTTP/2 request would result in a crash when the server actually tries to HTTP/2 PUSH a resource
    afterwards. Configuring the HTTP/2 feature via H2Push off will mitigate this vulnerability for unpatched
    servers. (CVE-2020-9490)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1490.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11984");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11993");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-9490");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update httpd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11984");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'httpd-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'httpd-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'httpd-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'httpd-debuginfo-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'httpd-debuginfo-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'httpd-debuginfo-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'httpd-devel-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'httpd-devel-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'httpd-devel-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'httpd-filesystem-2.4.46-1.amzn2', 'release':'AL2'},
    {'reference':'httpd-manual-2.4.46-1.amzn2', 'release':'AL2'},
    {'reference':'httpd-tools-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'httpd-tools-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'httpd-tools-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mod_ldap-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mod_ldap-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mod_ldap-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mod_md-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mod_md-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mod_md-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mod_proxy_html-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mod_proxy_html-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mod_proxy_html-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mod_session-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mod_session-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mod_session-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'mod_ssl-2.4.46-1.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'mod_ssl-2.4.46-1.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'mod_ssl-2.4.46-1.amzn2', 'cpu':'x86_64', 'release':'AL2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / etc");
}
