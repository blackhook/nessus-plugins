##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1795.
##

include('compat.inc');

if (description)
{
  script_id(161457);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id("CVE-2022-25235");

  script_name(english:"Amazon Linux 2 : xmlrpc-c (ALAS-2022-1795)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of xmlrpc-c installed on the remote host is prior to 1.32.5-1905.svn2451. It is, therefore, affected by a
vulnerability as referenced in the ALAS2-2022-1795 advisory.

  - xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks
    for whether a UTF-8 character is valid in a certain context. (CVE-2022-25235)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1795.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-25235.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update xmlrpc-c' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlrpc-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlrpc-c-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlrpc-c-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlrpc-c-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlrpc-c-client++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlrpc-c-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlrpc-c-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

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
    {'reference':'xmlrpc-c-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-apps-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-apps-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-apps-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-c++-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-c++-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-c++-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-client++-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-client++-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-client++-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-client-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-client-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-client-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-debuginfo-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-debuginfo-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-debuginfo-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-devel-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-devel-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xmlrpc-c-devel-1.32.5-1905.svn2451.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xmlrpc-c / xmlrpc-c-apps / xmlrpc-c-c++ / etc");
}