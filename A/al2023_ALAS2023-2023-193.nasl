#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-193.
##

include('compat.inc');

if (description)
{
  script_id(176898);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_cve_id(
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27537",
    "CVE-2023-27538"
  );
  script_xref(name:"IAVA", value:"2023-A-0153-S");

  script_name(english:"Amazon Linux 2023 : curl, curl-minimal, libcurl (ALAS2023-2023-193)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-193 advisory.

  - A vulnerability in input validation exists in curl <8.0 during communication using the TELNET protocol may
    allow an attacker to pass on maliciously crafted user name and telnet options during server negotiation.
    The lack of proper input scrubbing allows an attacker to send content or perform option negotiation
    without the application's intent. This vulnerability could be exploited if an application allows user
    input, thereby enabling attackers to execute arbitrary code on the system. (CVE-2023-27533)

  - A path traversal vulnerability exists in curl <8.0.0 SFTP implementation causes the tilde (~) character to
    be wrongly replaced when used as a prefix in the first path element, in addition to its intended use as
    the first element to indicate a path relative to the user's home directory. Attackers can exploit this
    flaw to bypass filtering or execute arbitrary code by crafting a path like /~2/foo while accessing a
    server with a specific user. (CVE-2023-27534)

  - An authentication bypass vulnerability exists in libcurl <8.0.0 in the FTP connection reuse feature that
    can result in wrong credentials being used during subsequent transfers. Previously created connections are
    kept in a connection pool for reuse if they match the current setup. However, certain FTP settings such as
    CURLOPT_FTP_ACCOUNT, CURLOPT_FTP_ALTERNATIVE_TO_USER, CURLOPT_FTP_SSL_CCC, and CURLOPT_USE_SSL were not
    included in the configuration match checks, causing them to match too easily. This could lead to libcurl
    using the wrong credentials when performing a transfer, potentially allowing unauthorized access to
    sensitive information. (CVE-2023-27535)

  - An authentication bypass vulnerability exists libcurl <8.0.0 in the connection reuse feature which can
    reuse previously established connections with incorrect user permissions due to a failure to check for
    changes in the CURLOPT_GSSAPI_DELEGATION option. This vulnerability affects krb5/kerberos/negotiate/GSSAPI
    transfers and could potentially result in unauthorized access to sensitive information. The safest option
    is to not reuse connections if the CURLOPT_GSSAPI_DELEGATION option has been changed. (CVE-2023-27536)

  - A double free vulnerability exists in libcurl <8.0.0 when sharing HSTS data between separate handles.
    This sharing was introduced without considerations for do this sharing across separate threads but there
    was no indication of this fact in the documentation. Due to missing mutexes or thread locks, two threads
    sharing the same HSTS data could end up doing a double-free or use-after-free. (CVE-2023-27537)

  - An authentication bypass vulnerability exists in libcurl prior to v8.0.0 where it reuses a previously
    established SSH connection despite the fact that an SSH option was modified, which should have prevented
    reuse. libcurl maintains a pool of previously used connections to reuse them for subsequent transfers if
    the configurations match. However, two SSH settings were omitted from the configuration check, allowing
    them to match easily, potentially leading to the reuse of an inappropriate connection. (CVE-2023-27538)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-193.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27533.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27534.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27535.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27536.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27537.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-27538.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update curl --releasever 2023.0.20230607' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27533");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-27534");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-minimal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'curl-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debugsource-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-minimal-debuginfo-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-debuginfo-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-8.0.1-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-8.0.1-1.amzn2023', 'cpu':'i686', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-minimal-debuginfo-8.0.1-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / etc");
}