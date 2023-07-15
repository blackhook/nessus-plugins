#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0009. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127156);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2017-7829",
    "CVE-2017-7846",
    "CVE-2017-7847",
    "CVE-2017-7848",
    "CVE-2018-5089",
    "CVE-2018-5095",
    "CVE-2018-5096",
    "CVE-2018-5097",
    "CVE-2018-5098",
    "CVE-2018-5099",
    "CVE-2018-5102",
    "CVE-2018-5103",
    "CVE-2018-5104",
    "CVE-2018-5117"
  );

  script_name(english:"NewStart CGSL MAIN 5.04 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has thunderbird packages installed that are affected by
multiple vulnerabilities:

  - It is possible to spoof the sender's email address and
    display an arbitrary sender address to the email
    recipient. The real sender's address is not displayed if
    preceded by a null character in the display string. This
    vulnerability affects Thunderbird < 52.5.2.
    (CVE-2017-7829)

  - Crafted CSS in an RSS feed can leak and reveal local
    path strings, which may contain user name. This
    vulnerability affects Thunderbird < 52.5.2.
    (CVE-2017-7847)

  - RSS fields can inject new lines into the created email
    structure, modifying the message body. This
    vulnerability affects Thunderbird < 52.5.2.
    (CVE-2017-7848)

  - It is possible to execute JavaScript in the parsed RSS
    feed when RSS feed is viewed as a website, e.g. via
    View -> Feed article -> Website or in the standard
    format of View -> Feed article -> default format. This
    vulnerability affects Thunderbird < 52.5.2.
    (CVE-2017-7846)

  - Memory safety bugs were reported in Firefox 57 and
    Firefox ESR 52.5. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    that some of these could be exploited to run arbitrary
    code. This vulnerability affects Thunderbird < 52.6,
    Firefox ESR < 52.6, and Firefox < 58. (CVE-2018-5089)

  - An integer overflow vulnerability in the Skia library
    when allocating memory for edge builders on some systems
    with at least 8 GB of RAM. This results in the use of
    uninitialized memory, resulting in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.6, Firefox ESR < 52.6, and Firefox <
    58. (CVE-2018-5095)

  - A use-after-free vulnerability can occur while editing
    events in form elements on a page, resulting in a
    potentially exploitable crash. This vulnerability
    affects Firefox ESR < 52.6 and Thunderbird < 52.6.
    (CVE-2018-5096)

  - A use-after-free vulnerability can occur during XSL
    transformations when the source document for the
    transformation is manipulated by script content during
    the transformation. This results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.6, Firefox ESR < 52.6, and Firefox <
    58. (CVE-2018-5097)

  - A use-after-free vulnerability can occur when form input
    elements, focus, and selections are manipulated by
    script content. This results in a potentially
    exploitable crash. This vulnerability affects
    Thunderbird < 52.6, Firefox ESR < 52.6, and Firefox <
    58. (CVE-2018-5098)

  - A use-after-free vulnerability can occur when the widget
    listener is holding strong references to browser objects
    that have previously been freed, resulting in a
    potentially exploitable crash when these references are
    used. This vulnerability affects Thunderbird < 52.6,
    Firefox ESR < 52.6, and Firefox < 58. (CVE-2018-5099)

  - A use-after-free vulnerability can occur when
    manipulating HTML media elements with media streams,
    resulting in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 52.6, Firefox ESR <
    52.6, and Firefox < 58. (CVE-2018-5102)

  - A use-after-free vulnerability can occur during mouse
    event handling due to issues with multiprocess support.
    This results in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 52.6, Firefox ESR <
    52.6, and Firefox < 58. (CVE-2018-5103)

  - A use-after-free vulnerability can occur during font
    face manipulation when a font face is freed while still
    in use, resulting in a potentially exploitable crash.
    This vulnerability affects Thunderbird < 52.6, Firefox
    ESR < 52.6, and Firefox < 58. (CVE-2018-5104)

  - If right-to-left text is used in the addressbar with
    left-to-right alignment, it is possible in some
    circumstances to scroll this text to spoof the displayed
    URL. This issue could result in the wrong URL being
    displayed as a location, which can mislead users to
    believe they are on a different site than the one
    loaded. This vulnerability affects Thunderbird < 52.6,
    Firefox ESR < 52.6, and Firefox < 58. (CVE-2018-5117)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0009");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5104");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "thunderbird-52.6.0-1.el7.centos",
    "thunderbird-debuginfo-52.6.0-1.el7.centos"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
