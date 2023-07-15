##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0048. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160755);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-9948",
    "CVE-2020-9951",
    "CVE-2020-9983",
    "CVE-2020-13543",
    "CVE-2020-13584",
    "CVE-2021-1817",
    "CVE-2021-1820",
    "CVE-2021-1825",
    "CVE-2021-1826",
    "CVE-2021-30661"
  );
  script_xref(name:"IAVA", value:"2021-A-0202-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"NewStart CGSL MAIN 6.02 : webkit2gtk3 Multiple Vulnerabilities (NS-SA-2022-0048)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has webkit2gtk3 packages installed that are affected by
multiple vulnerabilities:

  - A code execution vulnerability exists in the WebSocket functionality of Webkit WebKitGTK 2.30.0. A
    specially crafted web page can trigger a use-after-free vulnerability which can lead to remote code
    execution. An attacker can get a user to visit a webpage to trigger this vulnerability. (CVE-2020-13543)

  - An exploitable use-after-free vulnerability exists in WebKitGTK browser version 2.30.1 x64. A specially
    crafted HTML web page can cause a use-after-free condition, resulting in a remote code execution. The
    victim needs to visit a malicious web site to trigger this vulnerability. (CVE-2020-13584)

  - A type confusion issue was addressed with improved memory handling. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9948)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.0.
    Processing maliciously crafted web content may lead to arbitrary code execution. (CVE-2020-9951)

  - An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in Safari
    14.0. Processing maliciously crafted web content may lead to code execution. (CVE-2020-9983)

  - A memory corruption issue was addressed with improved state management. This issue is fixed in macOS Big
    Sur 11.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5. Processing maliciously crafted web content may
    lead to arbitrary code execution. (CVE-2021-1817)

  - A memory initialization issue was addressed with improved memory handling. This issue is fixed in macOS
    Big Sur 11.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5. Processing maliciously crafted web content
    may result in the disclosure of process memory. (CVE-2021-1820)

  - An input validation issue was addressed with improved input validation. This issue is fixed in iTunes
    12.11.3 for Windows, iCloud for Windows 12.3, macOS Big Sur 11.3, Safari 14.1, watchOS 7.4, tvOS 14.5, iOS
    14.5 and iPadOS 14.5. Processing maliciously crafted web content may lead to a cross site scripting
    attack. (CVE-2021-1825)

  - A logic issue was addressed with improved restrictions. This issue is fixed in macOS Big Sur 11.3, iOS
    14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5. Processing maliciously crafted web content may lead to
    universal cross site scripting. (CVE-2021-1826)

  - A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.1,
    iOS 12.5.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5, macOS Big Sur 11.3. Processing maliciously
    crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may
    have been actively exploited.. (CVE-2021-30661)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0048");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-13543");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-13584");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-9948");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-9951");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-9983");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-1817");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-1820");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-1825");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-1826");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-30661");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL webkit2gtk3 packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30661");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-jsc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-jsc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:webkit2gtk3-jsc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'webkit2gtk3-2.30.4-1.el8',
    'webkit2gtk3-debuginfo-2.30.4-1.el8',
    'webkit2gtk3-debugsource-2.30.4-1.el8',
    'webkit2gtk3-devel-2.30.4-1.el8',
    'webkit2gtk3-devel-debuginfo-2.30.4-1.el8',
    'webkit2gtk3-doc-2.30.4-1.el8',
    'webkit2gtk3-jsc-2.30.4-1.el8',
    'webkit2gtk3-jsc-debuginfo-2.30.4-1.el8',
    'webkit2gtk3-jsc-devel-2.30.4-1.el8',
    'webkit2gtk3-jsc-devel-debuginfo-2.30.4-1.el8'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkit2gtk3');
}
