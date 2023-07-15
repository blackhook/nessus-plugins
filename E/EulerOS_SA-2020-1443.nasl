#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135605);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-9096",
    "CVE-2016-7798",
    "CVE-2017-17742",
    "CVE-2017-9224",
    "CVE-2017-9227",
    "CVE-2017-9228",
    "CVE-2017-9229",
    "CVE-2018-1000073",
    "CVE-2018-1000074",
    "CVE-2018-1000077",
    "CVE-2018-1000078",
    "CVE-2018-1000079",
    "CVE-2019-16254",
    "CVE-2019-8321"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : ruby (EulerOS-SA-2020-1443)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ruby packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - An issue was discovered in RubyGems 2.6 and later
    through 3.0.2. Since Gem::UserInteraction#verbose calls
    say without escaping, escape sequence injection is
    possible.(CVE-2019-8321)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A SIGSEGV occurs in
    left_adjust_char_head() during regular expression
    compilation. Invalid handling of reg->dmax in
    forward_search_range() could result in an invalid
    pointer dereference, normally as an immediate
    denial-of-service condition.(CVE-2017-9229)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A stack out-of-bounds read occurs in
    mbc_enc_len() during regular expression searching.
    Invalid handling of reg->dmin in forward_search_range()
    could result in an invalid pointer dereference, as an
    out-of-bounds read from a stack buffer.(CVE-2017-9227)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A heap out-of-bounds write occurs in
    bitset_set_range() during regular expression
    compilation due to an uninitialized variable from an
    incorrect state transition. An incorrect state
    transition in parse_char_class() could create an
    execution path that leaves a critical local variable
    uninitialized until it's used as an index, resulting in
    an out-of-bounds write memory
    corruption.(CVE-2017-9228)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A stack out-of-bounds read occurs in
    match_at() during regular expression searching. A
    logical error involving order of validation and access
    in match_at() could result in an out-of-bounds read
    from a stack buffer.(CVE-2017-9224)

  - A SMTP command injection flaw was found in the way
    Ruby's Net::SMTP module handled CRLF sequences in
    certain SMTP commands. An attacker could potentially
    use this flaw to inject SMTP commands in a SMTP session
    in order to facilitate phishing attacks or spam
    campaigns.(CVE-2015-9096)

  - Constructed ASN.1 types with a recursive definition
    (such as can be found in PKCS7) could eventually exceed
    the stack given malicious input with excessive
    recursion. This could result in a Denial Of Service
    attack. There are no such structures used within
    SSL/TLS that come from untrusted sources so this is
    considered safe. Fixed in OpenSSL 1.1.0h (Affected
    1.1.0-1.1.0g). Fixed in OpenSSL 1.0.2o (Affected
    1.0.2b-1.0.2n).(CVE-2016-7798)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Directory
    Traversal vulnerability in gem installation that can
    result in the gem could write to arbitrary filesystem
    locations during installation. This attack appear to be
    exploitable via the victim must install a malicious
    gem. This vulnerability appears to have been fixed in
    2.7.6.(CVE-2018-1000079)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Cross Site
    Scripting (XSS) vulnerability in gem server display of
    homepage attribute that can result in XSS. This attack
    appear to be exploitable via the victim must browse to
    a malicious gem on a vulnerable gem server. This
    vulnerability appears to have been fixed in
    2.7.6.(CVE-2018-1000078)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Improper Input
    Validation vulnerability in ruby gems specification
    homepage attribute that can result in a malicious gem
    could set an invalid homepage URL. This vulnerability
    appears to have been fixed in 2.7.6.(CVE-2018-1000077)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a
    Deserialization of Untrusted Data vulnerability in
    owner command that can result in code execution. This
    attack appear to be exploitable via victim must run the
    `gem owner` command on a gem with a specially crafted
    YAML file. This vulnerability appears to have been
    fixed in 2.7.6.(CVE-2018-1000074)

  - RubyGems version Ruby 2.2 series: 2.2.9 and earlier,
    Ruby 2.3 series: 2.3.6 and earlier, Ruby 2.4 series:
    2.4.3 and earlier, Ruby 2.5 series: 2.5.0 and earlier,
    prior to trunk revision 62422 contains a Directory
    Traversal vulnerability in install_location function of
    package.rb that can result in path traversal when
    writing to a symlinked basedir outside of the root.
    This vulnerability appears to have been fixed in
    2.7.6.(CVE-2018-1000073)

  - Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before
    2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1 allows an
    HTTP Response Splitting attack. An attacker can inject
    a crafted key and value into an HTTP response for the
    HTTP server of WEBrick.(CVE-2017-17742)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x
    through 2.6.4 allows HTTP Response Splitting. If a
    program using WEBrick inserts untrusted input into the
    response header, an attacker can exploit it to insert a
    newline character to split a header, and inject
    malicious content to deceive clients. NOTE: this issue
    exists because of an incomplete fix for CVE-2017-17742,
    which addressed the CRLF vector, but did not address an
    isolated CR or an isolated LF.(CVE-2019-16254)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1443
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cbb87e3");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygems");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ruby-2.0.0.648-33.h19.eulerosv2r7",
        "ruby-irb-2.0.0.648-33.h19.eulerosv2r7",
        "ruby-libs-2.0.0.648-33.h19.eulerosv2r7",
        "rubygem-bigdecimal-1.2.0-33.h19.eulerosv2r7",
        "rubygem-io-console-0.4.2-33.h19.eulerosv2r7",
        "rubygem-json-1.7.7-33.h19.eulerosv2r7",
        "rubygem-psych-2.0.0-33.h19.eulerosv2r7",
        "rubygem-rdoc-4.0.0-33.h19.eulerosv2r7",
        "rubygems-2.0.14.1-33.h19.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
