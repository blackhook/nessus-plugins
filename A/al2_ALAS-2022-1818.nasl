##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1818.
##

include('compat.inc');

if (description)
{
  script_id(163228);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/23");

  script_cve_id(
    "CVE-2021-4140",
    "CVE-2021-32810",
    "CVE-2021-38496",
    "CVE-2021-38497",
    "CVE-2021-38498",
    "CVE-2021-38500",
    "CVE-2021-38501",
    "CVE-2021-38502",
    "CVE-2021-38503",
    "CVE-2021-43529",
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
  script_xref(name:"IAVA", value:"2021-A-0461-S");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2022-1818)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of thunderbird installed on the remote host is prior to 91.6.0-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2022-1818 advisory.

  - crossbeam-deque is a package of work-stealing deques for building task schedulers when programming in
    Rust. In versions prior to 0.7.4 and 0.8.0, the result of the race condition is that one or more tasks in
    the worker queue can be popped twice instead of other tasks that are forgotten and never popped. If tasks
    are allocated on the heap, this can cause double free and a memory leak. If not, this still can cause a
    logical bug. Crates using `Stealer::steal`, `Stealer::steal_batch`, or `Stealer::steal_batch_and_pop` are
    affected by this issue. This has been fixed in crossbeam-deque 0.8.1 and 0.7.4. (CVE-2021-32810)

  - During operations on MessageTasks, a task may have been removed while it was still scheduled, resulting in
    memory corruption and a potentially exploitable crash. This vulnerability affects Thunderbird < 78.15,
    Thunderbird < 91.2, Firefox ESR < 91.2, Firefox ESR < 78.15, and Firefox < 93. (CVE-2021-38496)

  - Through use of reportValidity() and window.open(), a plain-text validation message could have been
    overlaid on another origin, leading to possible user confusion and spoofing attacks. This vulnerability
    affects Firefox < 93, Thunderbird < 91.2, and Firefox ESR < 91.2. (CVE-2021-38497)

  - During process shutdown, a document could have caused a use-after-free of a languages service object,
    leading to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox < 93,
    Thunderbird < 91.2, and Firefox ESR < 91.2. (CVE-2021-38498)

  - Mozilla developers reported memory safety bugs present in Firefox 92 and Firefox ESR 91.1. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.15, Thunderbird < 91.2,
    Firefox ESR < 91.2, Firefox ESR < 78.15, and Firefox < 93. (CVE-2021-38500)

  - Mozilla developers reported memory safety bugs present in Firefox 92 and Firefox ESR 91.1. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 93, Thunderbird < 91.2, and
    Firefox ESR < 91.2. (CVE-2021-38501)

  - Thunderbird ignored the configuration to require STARTTLS security for an SMTP connection. A MITM could
    perform a downgrade attack to intercept transmitted messages, or could take control of the authenticated
    session to execute SMTP commands chosen by the MITM. If an unprotected authentication method was
    configured, the MITM could obtain the authentication credentials, too. This vulnerability affects
    Thunderbird < 91.2. (CVE-2021-38502)

  - Mozilla: Iframe sandbox bypass with XSLT (CVE-2021-4140)

  - Mozilla: Race condition when playing audio files (CVE-2022-22737)

  - Mozilla: Heap-buffer-overflow in blendGaussianBlur (CVE-2022-22738)

  - Mozilla: Missing throttling on external protocol launch dialog (CVE-2022-22739)

  - Mozilla: Use-after-free of ChannelEventQueue::mOwner (CVE-2022-22740)

  - Mozilla: Browser window spoof using fullscreen mode (CVE-2022-22741)

  - Mozilla: Out-of-bounds memory access when inserting text in edit mode (CVE-2022-22742)

  - When navigating from inside an iframe while requesting fullscreen access, an attacker-controlled tab could
    have made the browser unable to leave fullscreen mode.  (CVE-2022-22743)

  - Mozilla: Leaking cross-origin URLs through securitypolicyviolation event (CVE-2022-22745)

  - Mozilla: Crash when handling empty pkcs7 sequence (CVE-2022-22747)

  - Mozilla: Spoofed origin on external protocol launch dialog (CVE-2022-22748)

  - Mozilla: Memory safety bugs fixed in Firefox 96 and Firefox ESR 91.5 (CVE-2022-22751)

  - If a user installed an extension of a particular type, the extension could have auto-updated itself and
    while doing so, bypass the prompt which grants the new version the new requested permissions.
    (CVE-2022-22754)

  - If a user was convinced to drag and drop an image to their desktop or other folder, the resulting object
    could have been changed into an executable script which would have run arbitrary code after the user
    clicked on it.  (CVE-2022-22756)

  - If a document created a sandboxed iframe without <code>allow-scripts</code>, and subsequently appended an
    element to the iframe's document that e.g. had a JavaScript event handler - the event handler would have
    run despite the iframe's sandbox.  (CVE-2022-22759)

  - When importing resources using Web Workers, error messages would distinguish the difference between
    <code>application/javascript</code> responses and non-script responses.  This could have been abused to
    learn information cross-origin.  (CVE-2022-22760)

  - Web-accessible extension pages (pages with a moz-extension:// scheme) were not correctly enforcing the
    frame-ancestors directive when it was used in the Web Extension's Content Security Policy.
    (CVE-2022-22761)

  - When a worker is shutdown, it was possible to cause script to run late in the lifecycle, at a point after
    where it should not be possible.  (CVE-2022-22763)

  - Mozilla developers and community members Paul Adenot and the Mozilla Fuzzing Team reported memory safety
    bugs present in Thunderbird 91.5. Some of these bugs showed evidence of memory corruption and we presume
    that with enough effort some of these could have been exploited to run arbitrary code.  (CVE-2022-22764)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1818.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32810.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38496.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38497.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38498.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38500.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38501.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38502.html");
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'thunderbird-91.6.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-91.6.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-91.6.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-91.6.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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