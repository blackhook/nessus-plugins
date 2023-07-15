#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1700.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153416);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/07");

  script_cve_id(
    "CVE-2021-22898",
    "CVE-2021-22922",
    "CVE-2021-22923",
    "CVE-2021-22924",
    "CVE-2021-22925"
  );
  script_xref(name:"IAVA", value:"2021-A-0352-S");
  script_xref(name:"ALAS", value:"2021-1700");

  script_name(english:"Amazon Linux 2 : curl (ALAS-2021-1700)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of curl installed on the remote host is prior to 7.76.1-7. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1700 advisory.

  - curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as
    `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a
    flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized
    data from a stack based buffer to the server, resulting in potentially revealing sensitive internal
    information to the server using a clear-text network protocol. (CVE-2021-22898)

  - When curl is instructed to download content using the metalink feature, thecontents is verified against a
    hash provided in the metalink XML file.The metalink XML file points out to the client how to get the same
    contentfrom a set of different URLs, potentially hosted by different servers and theclient can then
    download the file from one or several of them. In a serial orparallel manner.If one of the servers hosting
    the contents has been breached and the contentsof the specific file on that server is replaced with a
    modified payload, curlshould detect this when the hash of the file mismatches after a completeddownload.
    It should remove the contents and instead try getting the contentsfrom another URL. This is not done, and
    instead such a hash mismatch is onlymentioned in text and the potentially malicious content is kept in the
    file ondisk. (CVE-2021-22922)

  - When curl is instructed to get content using the metalink feature, and a user name and password are used
    to download the metalink XML file, those same credentials are then subsequently passed on to each of the
    servers from which curl will download or try to download the contents from. Often contrary to the user's
    expectations and intentions and without telling the user it happened. (CVE-2021-22923)

  - libcurl keeps previously used connections in a connection pool for subsequenttransfers to reuse, if one of
    them matches the setup.Due to errors in the logic, the config matching function did not take 'issuercert'
    into account and it compared the involved paths *case insensitively*,which could lead to libcurl reusing
    wrong connections.File paths are, or can be, case sensitive on many systems but not all, and caneven vary
    depending on used file systems.The comparison also didn't include the 'issuer cert' which a transfer can
    setto qualify how to verify the server certificate. (CVE-2021-22924)

  - curl supports the `-t` command line option, known as `CURLOPT_TELNETOPTIONS`in libcurl. This rarely used
    option is used to send variable=content pairs toTELNET servers.Due to flaw in the option parser for
    sending `NEW_ENV` variables, libcurlcould be made to pass on uninitialized data from a stack based buffer
    to theserver. Therefore potentially revealing sensitive internal information to theserver using a clear-
    text network protocol.This could happen because curl did not call and use sscanf() correctly whenparsing
    the string provided by the application. (CVE-2021-22925)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1700.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22898");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22922");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22923");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22924");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-22925");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update curl' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22925");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-22922");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'curl-7.76.1-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-7.76.1-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-7.76.1-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.76.1-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.76.1-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'curl-debuginfo-7.76.1-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.76.1-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.76.1-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-7.76.1-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.76.1-7.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.76.1-7.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libcurl-devel-7.76.1-7.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var allowmaj = NULL;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / etc");
}