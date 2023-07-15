#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129184);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2015-9096",
    "CVE-2017-9224",
    "CVE-2017-9227",
    "CVE-2017-9228",
    "CVE-2017-9229"
  );

  script_name(english:"EulerOS 2.0 SP5 : ruby (EulerOS-SA-2019-1990)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ruby packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - A SMTP command injection flaw was found in the way
    Ruby's Net::SMTP module handled CRLF sequences in
    certain SMTP commands. An attacker could potentially
    use this flaw to inject SMTP commands in a SMTP session
    in order to facilitate phishing attacks or spam
    campaigns.(CVE-2015-9096)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A stack out-of-bounds read occurs in
    match_at() during regular expression searching. A
    logical error involving order of validation and access
    in match_at() could result in an out-of-bounds read
    from a stack buffer.(CVE-2017-9224)

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
    mbc_enc_len() during regular expression searching.
    Invalid handling of reg-i1/4zdmin in
    forward_search_range() could result in an invalid
    pointer dereference, as an out-of-bounds read from a
    stack buffer.(CVE-2017-9227)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A SIGSEGV occurs in
    left_adjust_char_head() during regular expression
    compilation. Invalid handling of reg-i1/4zdmax in
    forward_search_range() could result in an invalid
    pointer dereference, normally as an immediate
    denial-of-service condition.(CVE-2017-9229)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1990
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69f1ede8");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ruby-2.0.0.648-33.h16.eulerosv2r7",
        "ruby-irb-2.0.0.648-33.h16.eulerosv2r7",
        "ruby-libs-2.0.0.648-33.h16.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
