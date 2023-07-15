##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1828.
##

include('compat.inc');

if (description)
{
  script_id(163319);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/20");

  script_cve_id(
    "CVE-2022-1834",
    "CVE-2022-2226",
    "CVE-2022-31736",
    "CVE-2022-31737",
    "CVE-2022-31738",
    "CVE-2022-31740",
    "CVE-2022-31741",
    "CVE-2022-31742",
    "CVE-2022-31747"
  );
  script_xref(name:"IAVA", value:"2022-A-0226-S");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2022-1828)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of thunderbird installed on the remote host is prior to 91.11.0-2. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2022-1828 advisory.

  - When displaying the sender of an email, and the sender name contained the Braille Pattern Blank space
    character multiple times, Thunderbird would have displayed all the spaces. This could have been used by an
    attacker to send an email message with the attacker's digital signature, that was shown with an arbitrary
    sender email address chosen by the attacker. If the sender name started with a false email address,
    followed by many Braille space characters, the attacker's email address was not visible. Because
    Thunderbird compared the invisible sender address with the signature's email address, if the signing key
    or certificate was accepted by Thunderbird, the email was shown as having a valid digital signature.
    (CVE-2022-1834)

  - Mozilla: Cross-Origin resource's length leaked (CVE-2022-31736)

  - A malicious webpage could have caused an out-of-bounds write in WebGL, leading to memory corruption and a
    potentially exploitable crash.  (CVE-2022-31737)

  - Mozilla: Browser window spoof using fullscreen mode (CVE-2022-31738)

  - On arm64, WASM code could have resulted in incorrect assembly generation leading to a register allocation
    problem, and a potentially exploitable crash.  (CVE-2022-31740)

  - Mozilla: Uninitialized variable leads to invalid memory read (CVE-2022-31741)

  - Mozilla: Querying a WebAuthn token with a large number of allowCredential entries may have leaked cross-
    origin information (CVE-2022-31742)

  - Mozilla developers Andrew McCreight, Nicolas B. Pierron, and the Mozilla Fuzzing Team reported memory
    safety bugs present in Firefox 100 and Firefox ESR 91.9. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort some of these could have been exploited to run arbitrary
    code.  (CVE-2022-31747)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1828.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/../../faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1834.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2226.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31736.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31737.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31738.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31740.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31741.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31742.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-31747.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update thunderbird' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31747");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'thunderbird-91.11.0-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-91.11.0-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-91.11.0-2.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-91.11.0-2.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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