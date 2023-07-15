#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1672.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150994);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id("CVE-2021-31618");
  script_xref(name:"IAVA", value:"2021-A-0259-S");
  script_xref(name:"ALAS", value:"2021-1672");

  script_name(english:"Amazon Linux 2 : httpd (ALAS-2021-1672)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of httpd installed on the remote host is prior to 2.4.46-2. It is, therefore, affected by a vulnerability as
referenced in the ALAS2-2021-1672 advisory.

  - Apache HTTP Server protocol handler for the HTTP/2 protocol checks received request headers against the
    size limitations as configured for the server and used for the HTTP/1 protocol as well. On violation of
    these restrictions and HTTP response is sent to the client with a status code indicating why the request
    was rejected. This rejection response was not fully initialised in the HTTP/2 protocol handler if the
    offending header was the very first one received or appeared in a a footer. This led to a NULL pointer
    dereference on initialised memory, crashing reliably the child process. Since such a triggering HTTP/2
    request is easy to craft and submit, this can be exploited to DoS the server. This issue affected
    mod_http2 1.15.17 and Apache HTTP Server version 2.4.47 only. Apache HTTP Server 2.4.47 was never
    released. (CVE-2021-31618)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1672.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-31618");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update httpd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31618");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'httpd-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-debuginfo-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-debuginfo-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-debuginfo-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-devel-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-filesystem-2.4.46-2.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-manual-2.4.46-2.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'httpd-tools-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ldap-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_md-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_proxy_html-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_proxy_html-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_proxy_html-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_session-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-2.4.46-2.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-2.4.46-2.amzn2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mod_ssl-2.4.46-2.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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