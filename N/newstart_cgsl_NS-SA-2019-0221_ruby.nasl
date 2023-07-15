#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0221. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131412);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2017-17742",
    "CVE-2018-6914",
    "CVE-2018-8777",
    "CVE-2018-8778",
    "CVE-2018-8779",
    "CVE-2018-8780",
    "CVE-2018-16396",
    "CVE-2018-1000073",
    "CVE-2018-1000074",
    "CVE-2018-1000075",
    "CVE-2018-1000076",
    "CVE-2018-1000077",
    "CVE-2018-1000078",
    "CVE-2018-1000079"
  );
  script_bugtraq_id(
    103683,
    103684,
    103686,
    103693,
    103739,
    103767,
    105955
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : ruby Multiple Vulnerabilities (NS-SA-2019-0221)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has ruby packages installed that are affected by
multiple vulnerabilities:

  - In Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before
    2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1, an
    attacker controlling the unpacking format (similar to
    format string vulnerabilities) can trigger a buffer
    under-read in the String#unpack method, resulting in a
    massive and controlled information disclosure.
    (CVE-2018-8778)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Directory
    Traversal vulnerability in install_location function of
    package.rb that can result in path traversal when
    writing to a symlinked basedir outside of the root. This
    vulnerability appears to have been fixed in 2.7.6.
    (CVE-2018-1000073)

  - In Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before
    2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1, the
    Dir.open, Dir.new, Dir.entries and Dir.empty? methods do
    not check NULL characters. When using the corresponding
    method, unintentional directory traversal may be
    performed. (CVE-2018-8780)

  - Directory traversal vulnerability in the Dir.mktmpdir
    method in the tmpdir library in Ruby before 2.2.10,
    2.3.x before 2.3.7, 2.4.x before 2.4.4, 2.5.x before
    2.5.1, and 2.6.0-preview1 might allow attackers to
    create arbitrary directories or files via a .. (dot dot)
    in the prefix argument. (CVE-2018-6914)

  - In Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before
    2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1, an
    attacker can pass a large HTTP request with a crafted
    header to WEBrick server or a crafted body to WEBrick
    server/handler and cause a denial of service (memory
    consumption). (CVE-2018-8777)

  - Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before
    2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1 allows an
    HTTP Response Splitting attack. An attacker can inject a
    crafted key and value into an HTTP response for the HTTP
    server of WEBrick. (CVE-2017-17742)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Deserialization
    of Untrusted Data vulnerability in owner command that
    can result in code execution. This attack appear to be
    exploitable via victim must run the `gem owner` command
    on a gem with a specially crafted YAML file. This
    vulnerability appears to have been fixed in 2.7.6.
    (CVE-2018-1000074)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Cross Site
    Scripting (XSS) vulnerability in gem server display of
    homepage attribute that can result in XSS. This attack
    appear to be exploitable via the victim must browse to a
    malicious gem on a vulnerable gem server. This
    vulnerability appears to have been fixed in 2.7.6.
    (CVE-2018-1000078)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Directory
    Traversal vulnerability in gem installation that can
    result in the gem could write to arbitrary filesystem
    locations during installation. This attack appear to be
    exploitable via the victim must install a malicious gem.
    This vulnerability appears to have been fixed in 2.7.6.
    (CVE-2018-1000079)

  - An issue was discovered in Ruby before 2.3.8, 2.4.x
    before 2.4.5, 2.5.x before 2.5.2, and 2.6.x before
    2.6.0-preview3. It does not taint strings that result
    from unpacking tainted strings with some formats.
    (CVE-2018-16396)

  - In Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before
    2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1, the
    UNIXServer.open and UNIXSocket.open methods are not
    checked for null characters. It may be connected to an
    unintended socket. (CVE-2018-8779)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a infinite loop
    caused by negative size vulnerability in ruby gem
    package tar header that can result in a negative size
    could cause an infinite loop.. This vulnerability
    appears to have been fixed in 2.7.6. (CVE-2018-1000075)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Improper
    Verification of Cryptographic Signature vulnerability in
    package.rb that can result in a mis-signed gem could be
    installed, as the tarball would contain multiple gem
    signatures.. This vulnerability appears to have been
    fixed in 2.7.6. (CVE-2018-1000076)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Improper Input
    Validation vulnerability in ruby gems specification
    homepage attribute that can result in a malicious gem
    could set an invalid homepage URL. This vulnerability
    appears to have been fixed in 2.7.6. (CVE-2018-1000077)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0221");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ruby packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8780");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1000076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "ruby-2.0.0.648-36.el7",
    "ruby-debuginfo-2.0.0.648-36.el7",
    "ruby-devel-2.0.0.648-36.el7",
    "ruby-doc-2.0.0.648-36.el7",
    "ruby-irb-2.0.0.648-36.el7",
    "ruby-libs-2.0.0.648-36.el7",
    "ruby-tcltk-2.0.0.648-36.el7",
    "rubygem-bigdecimal-1.2.0-36.el7",
    "rubygem-io-console-0.4.2-36.el7",
    "rubygem-json-1.7.7-36.el7",
    "rubygem-minitest-4.3.2-36.el7",
    "rubygem-psych-2.0.0-36.el7",
    "rubygem-rake-0.9.6-36.el7",
    "rubygem-rdoc-4.0.0-36.el7",
    "rubygems-2.0.14.1-36.el7",
    "rubygems-devel-2.0.14.1-36.el7"
  ],
  "CGSL MAIN 5.04": [
    "ruby-2.0.0.648-36.el7",
    "ruby-debuginfo-2.0.0.648-36.el7",
    "ruby-devel-2.0.0.648-36.el7",
    "ruby-doc-2.0.0.648-36.el7",
    "ruby-irb-2.0.0.648-36.el7",
    "ruby-libs-2.0.0.648-36.el7",
    "ruby-tcltk-2.0.0.648-36.el7",
    "rubygem-bigdecimal-1.2.0-36.el7",
    "rubygem-io-console-0.4.2-36.el7",
    "rubygem-json-1.7.7-36.el7",
    "rubygem-minitest-4.3.2-36.el7",
    "rubygem-psych-2.0.0-36.el7",
    "rubygem-rake-0.9.6-36.el7",
    "rubygem-rdoc-4.0.0-36.el7",
    "rubygems-2.0.14.1-36.el7",
    "rubygems-devel-2.0.14.1-36.el7"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
