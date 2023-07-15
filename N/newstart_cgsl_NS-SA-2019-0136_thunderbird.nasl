#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0136. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127395);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-5150",
    "CVE-2018-5154",
    "CVE-2018-5155",
    "CVE-2018-5159",
    "CVE-2018-5161",
    "CVE-2018-5162",
    "CVE-2018-5168",
    "CVE-2018-5170",
    "CVE-2018-5178",
    "CVE-2018-5183",
    "CVE-2018-5184",
    "CVE-2018-5185"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0136)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has thunderbird packages installed that are affected by
multiple vulnerabilities:

  - Using remote content in encrypted messages can lead to
    the disclosure of plaintext. This vulnerability affects
    Thunderbird ESR < 52.8 and Thunderbird < 52.8.
    (CVE-2018-5184)

  - Crafted message headers can cause a Thunderbird process
    to hang on receiving the message. This vulnerability
    affects Thunderbird ESR < 52.8 and Thunderbird < 52.8.
    (CVE-2018-5161)

  - Plaintext of decrypted emails can leak through the src
    attribute of remote images, or links. This vulnerability
    affects Thunderbird ESR < 52.8 and Thunderbird < 52.8.
    (CVE-2018-5162)

  - It is possible to spoof the filename of an attachment
    and display an arbitrary attachment name. This could
    lead to a user opening a remote attachment which is a
    different file type than expected. This vulnerability
    affects Thunderbird ESR < 52.8 and Thunderbird < 52.8.
    (CVE-2018-5170)

  - Plaintext of decrypted emails can leak through by user
    submitting an embedded form. This vulnerability affects
    Thunderbird ESR < 52.8 and Thunderbird < 52.8.
    (CVE-2018-5185)

  - A use-after-free vulnerability can occur while
    enumerating attributes during SVG animations with clip
    paths. This results in a potentially exploitable crash.
    This vulnerability affects Thunderbird < 52.8,
    Thunderbird ESR < 52.8, Firefox < 60, and Firefox ESR <
    52.8. (CVE-2018-5154)

  - A use-after-free vulnerability can occur while adjusting
    layout during SVG animations with text paths. This
    results in a potentially exploitable crash. This
    vulnerability affects Thunderbird < 52.8, Thunderbird
    ESR < 52.8, Firefox < 60, and Firefox ESR < 52.8.
    (CVE-2018-5155)

  - An integer overflow can occur in the Skia library due to
    32-bit integer use in an array without integer overflow
    checks, resulting in possible out-of-bounds writes. This
    could lead to a potentially exploitable crash
    triggerable by web content. This vulnerability affects
    Thunderbird < 52.8, Thunderbird ESR < 52.8, Firefox <
    60, and Firefox ESR < 52.8. (CVE-2018-5159)

  - A buffer overflow was found during UTF8 to Unicode
    string conversion within JavaScript with extremely large
    amounts of data. This vulnerability requires the use of
    a malicious or vulnerable legacy extension in order to
    occur. This vulnerability affects Thunderbird ESR <
    52.8, Thunderbird < 52.8, and Firefox ESR < 52.8.
    (CVE-2018-5178)

  - Mozilla developers backported selected changes in the
    Skia library. These changes correct memory corruption
    issues including invalid buffer reads and writes during
    graphic operations. This vulnerability affects
    Thunderbird ESR < 52.8, Thunderbird < 52.8, and Firefox
    ESR < 52.8. (CVE-2018-5183)

  - Memory safety bugs were reported in Firefox 59, Firefox
    ESR 52.7, and Thunderbird 52.7. Some of these bugs
    showed evidence of memory corruption and we presume that
    with enough effort that some of these could be exploited
    to run arbitrary code. This vulnerability affects
    Thunderbird < 52.8, Thunderbird ESR < 52.8, Firefox <
    60, and Firefox ESR < 52.8. (CVE-2018-5150)

  - Sites can bypass security checks on permissions to
    install lightweight themes by manipulating the baseURI
    property of the theme element. This could allow a
    malicious site to install a theme without user
    interaction which could contain offensive or
    embarrassing images. This vulnerability affects
    Thunderbird < 52.8, Thunderbird ESR < 52.8, Firefox <
    60, and Firefox ESR < 52.8. (CVE-2018-5168)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0136");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5183");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "thunderbird-52.8.0-2.el6.centos",
    "thunderbird-debuginfo-52.8.0-2.el6.centos"
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
