#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1763.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158719);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-4140",
    "CVE-2022-22737",
    "CVE-2022-22738",
    "CVE-2022-22739",
    "CVE-2022-22740",
    "CVE-2022-22741",
    "CVE-2022-22742",
    "CVE-2022-22743",
    "CVE-2022-22745",
    "CVE-2022-22747",
    "CVE-2022-22748",
    "CVE-2022-22751",
    "CVE-2022-22754",
    "CVE-2022-22756",
    "CVE-2022-22759",
    "CVE-2022-22760",
    "CVE-2022-22761",
    "CVE-2022-22763",
    "CVE-2022-22764"
  );
  script_xref(name:"IAVA", value:"2022-A-0017-S");
  script_xref(name:"IAVA", value:"2022-A-0079-S");
  script_xref(name:"ALAS", value:"2022-1763");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2022-1763)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of thunderbird installed on the remote host is prior to 91.6.0-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2022-1763 advisory.

  - Mozilla developers Paul Adenot and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox
    96 and Firefox ESR 91.5. Some of these bugs showed evidence of memory corruption and we presume that with
    enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects
    Firefox < 97, Thunderbird < 91.6, and Firefox ESR < 91.6. (CVE-2022-22764)

  - It was possible to construct specific XSLT markup that would be able to bypass an iframe sandbox. This
    vulnerability affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5. (CVE-2021-4140)

  - Constructing audio sinks could have lead to a race condition when playing audio files and closing windows.
    This could have lead to a use-after-free causing a potentially exploitable crash. This vulnerability
    affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22737)

  - Applying a CSS filter effect could have accessed out of bounds memory. This could have lead to a heap-
    buffer-overflow causing a potentially exploitable crash. This vulnerability affects Firefox ESR < 91.5,
    Firefox < 96, and Thunderbird < 91.5. (CVE-2022-22738)

  - Malicious websites could have tricked users into accepting launching a program to handle an external URL
    protocol. This vulnerability affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5.
    (CVE-2022-22739)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4140.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22737.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22738.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22739.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22740.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22741.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22742.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22743.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22745.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22747.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22748.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22751.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22754.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22756.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22759.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22760.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22761.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22763.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-22764.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update thunderbird' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22764");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4140");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'thunderbird-91.6.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-91.6.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-91.6.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-91.6.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}