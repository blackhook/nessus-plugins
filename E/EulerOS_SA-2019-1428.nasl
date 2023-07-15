#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124931);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2012-4464",
    "CVE-2012-4466",
    "CVE-2012-4522",
    "CVE-2012-5371",
    "CVE-2013-2065",
    "CVE-2013-4073",
    "CVE-2013-4164",
    "CVE-2013-4287",
    "CVE-2013-4363",
    "CVE-2014-4975",
    "CVE-2014-8080",
    "CVE-2014-8090",
    "CVE-2018-8780",
    "CVE-2018-16395",
    "CVE-2018-16396"
  );
  script_bugtraq_id(
    55757,
    56115,
    56484,
    59881,
    60843,
    62281,
    62442,
    63873,
    68474,
    70935,
    71230
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : ruby (EulerOS-SA-2019-1428)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ruby packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - Ruby 1.8.7 before patchlevel 371, 1.9.3 before
    patchlevel 286, and 2.0 before revision r37068 allows
    context-dependent attackers to bypass safe-level
    restrictions and modify untainted strings via the
    name_err_mesg_to_str API function, which marks the
    string as tainted, a different vulnerability than
    CVE-2011-1005.(CVE-2012-4466)

  - The REXML parser in Ruby 1.9.x before 1.9.3 patchlevel
    551, 2.0.x before 2.0.0 patchlevel 598, and 2.1.x
    before 2.1.5 allows remote attackers to cause a denial
    of service (CPU and memory consumption) a crafted XML
    document containing an empty string in an entity that
    is used in a large number of nested entity references,
    aka an XML Entity Expansion (XEE) attack. NOTE: this
    vulnerability exists because of an incomplete fix for
    CVE-2013-1821 and CVE-2014-8080.(CVE-2014-8090)

  - Algorithmic complexity vulnerability in
    Gem::Version::VERSION_PATTERN in
    lib/rubygems/version.rb in RubyGems before 1.8.23.1,
    1.8.24 through 1.8.25, 2.0.x before 2.0.8, and 2.1.x
    before 2.1.0, as used in Ruby 1.9.0 through 2.0.0p247,
    allows remote attackers to cause a denial of service
    (CPU consumption) via a crafted gem version that
    triggers a large amount of backtracking in a regular
    expression.(CVE-2013-4287)

  - The REXML parser in Ruby 1.9.x before 1.9.3-p550, 2.0.x
    before 2.0.0-p594, and 2.1.x before 2.1.4 allows remote
    attackers to cause a denial of service (memory
    consumption) via a crafted XML document, aka an XML
    Entity Expansion (XEE) attack.(CVE-2014-8080)

  - The OpenSSL::SSL.verify_certificate_identity function
    in lib/openssl/ssl.rb in Ruby 1.8 before 1.8.7-p374,
    1.9 before 1.9.3-p448, and 2.0 before 2.0.0-p247 does
    not properly handle a '\\0' character in a domain name
    in the Subject Alternative Name field of an X.509
    certificate, which allows man-in-the-middle attackers
    to spoof arbitrary SSL servers via a crafted
    certificate issued by a legitimate Certification
    Authority, a related issue to
    CVE-2009-2408.(CVE-2013-4073)

  - The rb_get_path_check function in file.c in Ruby 1.9.3
    before patchlevel 286 and Ruby 2.0.0 before r37163
    allows context-dependent attackers to create files in
    unexpected locations or with unexpected names via a NUL
    byte in a file path.(CVE-2012-4522)

  - (1) DL and (2) Fiddle in Ruby 1.9 before 1.9.3
    patchlevel 426, and 2.0 before 2.0.0 patchlevel 195, do
    not perform taint checking for native functions, which
    allows context-dependent attackers to bypass intended
    $SAFE level restrictions.(CVE-2013-2065)

  - Algorithmic complexity vulnerability in
    Gem::Version::ANCHORED_VERSION_PATTERN in
    lib/rubygems/version.rb in RubyGems before 1.8.23.2,
    1.8.24 through 1.8.26, 2.0.x before 2.0.10, and 2.1.x
    before 2.1.5, as used in Ruby 1.9.0 through 2.0.0p247,
    allows remote attackers to cause a denial of service
    (CPU consumption) via a crafted gem version that
    triggers a large amount of backtracking in a regular
    expression. NOTE: this issue is due to an incomplete
    fix for CVE-2013-4287.(CVE-2013-4363)

  - Ruby (aka CRuby) 1.9 before 1.9.3-p327 and 2.0 before
    r37575 computes hash values without properly
    restricting the ability to trigger hash collisions
    predictably, which allows context-dependent attackers
    to cause a denial of service (CPU consumption) via
    crafted input to an application that maintains a hash
    table, as demonstrated by a universal multicollision
    attack against a variant of the MurmurHash2 algorithm,
    a different vulnerability than
    CVE-2011-4815.(CVE-2012-5371)

  - Off-by-one error in the encodes function in pack.c in
    Ruby 1.9.3 and earlier, and 2.x through 2.1.2, when
    using certain format string specifiers, allows
    context-dependent attackers to cause a denial of
    service (segmentation fault) via vectors that trigger a
    stack-based buffer overflow.(CVE-2014-4975)

  - Heap-based buffer overflow in Ruby 1.8, 1.9 before
    1.9.3-p484, 2.0 before 2.0.0-p353, 2.1 before 2.1.0
    preview2, and trunk before revision 43780 allows
    context-dependent attackers to cause a denial of
    service (segmentation fault) and possibly execute
    arbitrary code via a string that is converted to a
    floating point value, as demonstrated using (1) the
    to_f method or (2) JSON.parse.(CVE-2013-4164)

  - It was found that the methods from the Dir class did
    not properly handle strings containing the NULL byte.
    An attacker, able to inject NULL bytes in a path, could
    possibly trigger an unspecified behavior of the ruby
    script.(CVE-2018-8780)

  - Ruby 1.9.3 before patchlevel 286 and 2.0 before
    revision r37068 allows context-dependent attackers to
    bypass safe-level restrictions and modify untainted
    strings via the (1) exc_to_s or (2) name_err_to_s API
    function, which marks the string as tainted, a
    different vulnerability than CVE-2012-4466. NOTE: this
    issue might exist because of a CVE-2011-1005
    regression.(CVE-2012-4464)

  - An issue was discovered in the OpenSSL library in Ruby
    before 2.3.8, 2.4.x before 2.4.5, 2.5.x before 2.5.2,
    and 2.6.x before 2.6.0-preview3. When two
    OpenSSL::X509::Name objects are compared using ==,
    depending on the ordering, non-equal objects may return
    true. When the first argument is one character longer
    than the second, or the second argument contains a
    character that is one less than a character in the same
    position of the first argument, the result of == will
    be true. This could be leveraged to create an
    illegitimate certificate that may be accepted as
    legitimate and then used in signing or encryption
    operations.(CVE-2018-16395)

  - An issue was discovered in Ruby before 2.3.8, 2.4.x
    before 2.4.5, 2.5.x before 2.5.2, and 2.6.x before
    2.6.0-preview3. It does not taint strings that result
    from unpacking tainted strings with some
    formats.(CVE-2018-16396)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1428
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81cbe7ae");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8780");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["ruby-2.0.0.648-33.h12",
        "ruby-irb-2.0.0.648-33.h12",
        "ruby-libs-2.0.0.648-33.h12",
        "rubygem-bigdecimal-1.2.0-33.h12",
        "rubygem-io-console-0.4.2-33.h12",
        "rubygem-json-1.7.7-33.h12",
        "rubygem-psych-2.0.0-33.h12",
        "rubygem-rdoc-4.0.0-33.h12",
        "rubygems-2.0.14.1-33.h12"];

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
