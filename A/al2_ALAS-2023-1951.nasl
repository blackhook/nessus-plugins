#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2023-1951.
##

include('compat.inc');

if (description)
{
  script_id(171818);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/27");

  script_cve_id(
    "CVE-2021-4127",
    "CVE-2021-4129",
    "CVE-2022-2200",
    "CVE-2022-3266",
    "CVE-2022-34468",
    "CVE-2022-34470",
    "CVE-2022-34472",
    "CVE-2022-34479",
    "CVE-2022-34481",
    "CVE-2022-34484",
    "CVE-2022-40961",
    "CVE-2022-45414",
    "CVE-2022-46871",
    "CVE-2022-46872",
    "CVE-2022-46874",
    "CVE-2022-46877",
    "CVE-2022-46878",
    "CVE-2022-46880",
    "CVE-2022-46881",
    "CVE-2022-46882",
    "CVE-2023-23598",
    "CVE-2023-23599",
    "CVE-2023-23601",
    "CVE-2023-23602",
    "CVE-2023-23603",
    "CVE-2023-23605"
  );
  script_xref(name:"IAVA", value:"2023-A-0056-S");
  script_xref(name:"IAVA", value:"2022-A-0519-S");
  script_xref(name:"IAVA", value:"2022-A-0505-S");
  script_xref(name:"IAVA", value:"2023-A-0009-S");
  script_xref(name:"IAVA", value:"2022-A-0256-S");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2023-1951)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of thunderbird installed on the remote host is prior to 102.7.1-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2023-1951 advisory.

  - An out of date graphics library (Angle) likely contained vulnerabilities that could potentially be
    exploited. This vulnerability affects Thunderbird < 78.9 and Firefox ESR < 78.9. (CVE-2021-4127)

  - Mozilla developers and community members Julian Hector, Randell Jesup, Gabriele Svelto, Tyson Smith,
    Christian Holler, and Masayuki Nakano reported memory safety bugs present in Firefox 94. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 95, Firefox ESR < 91.4.0, and
    Thunderbird < 91.4.0. (CVE-2021-4129)

  - If an object prototype was corrupted by an attacker, they would have been able to set undesired attributes
    on a JavaScript object, leading to privileged code execution. This vulnerability affects Firefox < 102,
    Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-2200)

  - An out-of-bounds read can occur when decoding H264 video. This results in a potentially exploitable crash.
    This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and Firefox < 105. (CVE-2022-3266)

  - An iframe that was not permitted to run scripts could do so if the user clicked on a
    <code>javascript:</code> link. This vulnerability affects Firefox < 102, Firefox ESR < 91.11, Thunderbird
    < 102, and Thunderbird < 91.11. (CVE-2022-34468)

  - Session history navigations may have led to a use-after-free and potentially exploitable crash. This
    vulnerability affects Firefox < 102, Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11.
    (CVE-2022-34470)

  - If there was a PAC URL set and the server that hosts the PAC was not reachable, OCSP requests would have
    been blocked, resulting in incorrect error pages being shown. This vulnerability affects Firefox < 102,
    Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34472)

  - A malicious website that could create a popup could have resized the popup to overlay the address bar with
    its own content, resulting in potential user confusion or spoofing attacks. <br>*This bug only affects
    Thunderbird for Linux. Other operating systems are unaffected.*. This vulnerability affects Firefox < 102,
    Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34479)

  - In the <code>nsTArray_Impl::ReplaceElementsAt()</code> function, an integer overflow could have occurred
    when the number of elements to replace was too large for the container. This vulnerability affects Firefox
    < 102, Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34481)

  - The Mozilla Fuzzing Team reported potential vulnerabilities present in Thunderbird 91.10. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 102, Firefox ESR < 91.11,
    Thunderbird < 102, and Thunderbird < 91.11. (CVE-2022-34484)

  - During startup, a graphics driver with an unexpected name could lead to a stack-buffer overflow causing a
    potentially exploitable crash.<br>*This issue only affects Firefox for Android. Other operating systems
    are not affected.*. This vulnerability affects Firefox < 105. (CVE-2022-40961)

  - If a Thunderbird user quoted from an HTML email, for example by replying to the email, and the email
    contained either a VIDEO tag with the POSTER attribute or an OBJECT tag with a DATA attribute, a network
    request to the referenced remote URL was performed, regardless of a configuration to block remote content.
    An image loaded from the POSTER attribute was shown in the composer window. These issues could have given
    an attacker additional capabilities when targetting releases that did not yet have a fix for CVE-2022-3033
    which was reported around three months ago. This vulnerability affects Thunderbird < 102.5.1.
    (CVE-2022-45414)

  - An out of date library (libusrsctp) contained vulnerabilities that could potentially be exploited. This
    vulnerability affects Firefox < 108. (CVE-2022-46871)

  - An attacker who compromised a content process could have partially escaped the sandbox to read arbitrary
    files via clipboard-related IPC messages.<br>*This bug only affects Thunderbird for Linux. Other operating
    systems are unaffected.*. This vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird <
    102.6. (CVE-2022-46872)

  - A file with a long filename could have had its filename truncated to remove the valid extension, leaving a
    malicious extension in its place. This could potentially led to user confusion and the execution of
    malicious code.<br/>*Note*: This issue was originally included in the advisories for Thunderbird 102.6,
    but a patch (specific to Thunderbird) was omitted, resulting in it actually being fixed in Thunderbird
    102.6.1. This vulnerability affects Firefox < 108, Thunderbird < 102.6.1, Thunderbird < 102.6, and Firefox
    ESR < 102.6. (CVE-2022-46874)

  - By confusing the browser, the fullscreen notification could have been delayed or suppressed, resulting in
    potential user confusion or spoofing attacks. This vulnerability affects Firefox < 108. (CVE-2022-46877)

  - Mozilla developers Randell Jesup, Valentin Gosu, Olli Pettay, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Thunderbird 102.5. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird < 102.6. (CVE-2022-46878)

  - A missing check related to tex units could have led to a use-after-free and potentially exploitable
    crash.<br />*Note*: This advisory was added on December 13th, 2022 after we better understood the impact
    of the issue. The fix was included in the original release of Firefox 105. This vulnerability affects
    Firefox ESR < 102.6, Firefox < 105, and Thunderbird < 102.6. (CVE-2022-46880)

  - An optimization in WebGL was incorrect in some cases, and could have led to memory corruption and a
    potentially exploitable crash. This vulnerability affects Firefox < 106, Firefox ESR < 102.6, and
    Thunderbird < 102.6. (CVE-2022-46881)

  - A use-after-free in WebGL extensions could have led to a potentially exploitable crash. This vulnerability
    affects Firefox < 107, Firefox ESR < 102.6, and Thunderbird < 102.6. (CVE-2022-46882)

  - Mozilla: Arbitrary file read from GTK drag and drop on Linux (CVE-2023-23598)

  - Mozilla: Malicious command could be hidden in devtools output (CVE-2023-23599)

  - Mozilla: URL being dragged from cross-origin iframe into same tab triggers navigation (CVE-2023-23601)

  - Mozilla: Content Security Policy wasn't being correctly applied to WebSockets in WebWorkers
    (CVE-2023-23602)

  - Mozilla: Calls to <code>console.log</code> allowed bypasing Content Security Policy via format directive
    (CVE-2023-23603)

  - Mozilla: Memory safety bugs fixed in Firefox 109 and Firefox ESR 102.7 (CVE-2023-23605)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2023-1951.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4127.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-4129.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2200.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3266.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-34468.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-34470.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-34472.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-34479.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-34481.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-34484.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40961.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-45414.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46871.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46872.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46874.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46877.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46878.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46880.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46881.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46882.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23598.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23599.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23601.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23602.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23603.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-23605.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update thunderbird' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'thunderbird-102.7.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-102.7.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-102.7.1-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-102.7.1-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}