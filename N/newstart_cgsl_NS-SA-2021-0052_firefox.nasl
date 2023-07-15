##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0052. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147247);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id(
    "CVE-2020-6463",
    "CVE-2020-6514",
    "CVE-2020-12422",
    "CVE-2020-12424",
    "CVE-2020-12425",
    "CVE-2020-15648",
    "CVE-2020-15652",
    "CVE-2020-15653",
    "CVE-2020-15654",
    "CVE-2020-15656",
    "CVE-2020-15658",
    "CVE-2020-15659",
    "CVE-2020-15664",
    "CVE-2020-15669"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : firefox Multiple Vulnerabilities (NS-SA-2021-0052)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has firefox packages installed that are affected by multiple
vulnerabilities:

  - Use after free in ANGLE in Google Chrome prior to 81.0.4044.122 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6463)

  - Inappropriate implementation in WebRTC in Google Chrome prior to 84.0.4147.89 allowed an attacker in a
    privileged network position to potentially exploit heap corruption via a crafted SCTP stream.
    (CVE-2020-6514)

  - By observing the stack trace for JavaScript errors in web workers, it was possible to leak the result of a
    cross-origin redirect. This applied only to content that can be parsed as script. This vulnerability
    affects Firefox < 79, Firefox ESR < 68.11, Firefox ESR < 78.1, Thunderbird < 68.11, and Thunderbird <
    78.1. (CVE-2020-15652)

  - Mozilla developers and community members reported memory safety bugs present in Firefox 78 and Firefox ESR
    78.0. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some
    of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 79, Firefox
    ESR < 68.11, Firefox ESR < 78.1, Thunderbird < 68.11, and Thunderbird < 78.1. (CVE-2020-15659)

  - Using object or embed tags, it was possible to frame other websites, even if they disallowed framing using
    the X-Frame-Options header. This vulnerability affects Thunderbird < 78 and Firefox < 78.0.2.
    (CVE-2020-15648)

  - In non-standard configurations, a JPEG image created by JavaScript could have caused an internal variable
    to overflow, resulting in an out of bounds write, memory corruption, and a potentially exploitable crash.
    This vulnerability affects Firefox < 78. (CVE-2020-12422)

  - When constructing a permission prompt for WebRTC, a URI was supplied from the content process. This URI
    was untrusted, and could have been the URI of an origin that was previously granted permission; bypassing
    the prompt. This vulnerability affects Firefox < 78. (CVE-2020-12424)

  - Due to confusion processing a hyphen character in Date.parse(), a one-byte out of bounds read could have
    occurred, leading to potential information disclosure. This vulnerability affects Firefox < 78.
    (CVE-2020-12425)

  - An iframe sandbox element with the allow-popups flag could be bypassed when using noopener links. This
    could have led to security issues for websites relying on sandbox configurations that allowed popups and
    hosted arbitrary content. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird <
    78.1. (CVE-2020-15653)

  - JIT optimizations involving the Javascript arguments object could confuse later optimizations. This risk
    was already mitigated by various precautions in the code, resulting in this bug rated at only moderate
    severity. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird < 78.1.
    (CVE-2020-15656)

  - The code for downloading files did not properly take care of special characters, which led to an attacker
    being able to cut off the file ending at an earlier position, leading to a different file type being
    downloaded than shown in the dialog. This vulnerability affects Firefox ESR < 78.1, Firefox < 79, and
    Thunderbird < 78.1. (CVE-2020-15658)

  - When in an endless loop, a website specifying a custom cursor using CSS could make it look like the user
    is interacting with the user interface, when they are not. This could lead to a perceived broken state,
    especially when interactions with existing browser dialogs and warnings do not work. This vulnerability
    affects Firefox ESR < 78.1, Firefox < 79, and Thunderbird < 78.1. (CVE-2020-15654)

  - By holding a reference to the eval() function from an about:blank window, a malicious webpage could have
    gained access to the InstallTrigger object which would allow them to prompt the user to install an
    extension. Combined with user confusion, this could result in an unintended or malicious extension being
    installed. This vulnerability affects Firefox < 80, Thunderbird < 78.2, Thunderbird < 68.12, Firefox ESR <
    68.12, Firefox ESR < 78.2, and Firefox for Android < 80. (CVE-2020-15664)

  - When aborting an operation, such as a fetch, an abort signal may be deleted while alerting the objects to
    be notified. This results in a use-after-free and we presume that with enough effort it could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 68.12 and Thunderbird < 68.12.
    (CVE-2020-15669)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0052");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL firefox packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15659");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'firefox-78.2.0-2.el8_2',
    'firefox-debugsource-78.2.0-2.el8_2'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox');
}
