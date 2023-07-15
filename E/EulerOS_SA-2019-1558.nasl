#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125102);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id(
    "CVE-2014-8964",
    "CVE-2015-2327",
    "CVE-2015-2328",
    "CVE-2015-3217",
    "CVE-2015-5073",
    "CVE-2015-8380",
    "CVE-2015-8385",
    "CVE-2015-8386",
    "CVE-2015-8387",
    "CVE-2015-8388",
    "CVE-2015-8390",
    "CVE-2015-8391",
    "CVE-2015-8394",
    "CVE-2016-3191"
  );
  script_bugtraq_id(
    71206,
    75018,
    75430
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : pcre (EulerOS-SA-2019-1558)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the pcre packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - PCRE before 8.36 mishandles the /((?(R)a|(?1)))+/
    pattern and related patterns with certain recursion,
    which allows remote attackers to cause a denial of
    service (segmentation fault) or possibly have
    unspecified other impact via a crafted regular
    expression, as demonstrated by a JavaScript RegExp
    object encountered by Konqueror.(CVE-2015-2328)

  - PCRE before 8.38 mishandles the : and \\\\ substrings
    in character classes, which allows remote attackers to
    cause a denial of service (uninitialized memory read)
    or possibly have unspecified other impact via a crafted
    regular expression, as demonstrated by a JavaScript
    RegExp object encountered by Konqueror.(CVE-2015-8390)

  - Heap-based buffer overflow in the find_fixedlength
    function in pcre_compile.c in PCRE before 8.38 allows
    remote attackers to cause a denial of service (crash)
    or obtain sensitive information from heap memory and
    possibly bypass the ASLR protection mechanism via a
    crafted regular expression with an excess closing
    parenthesis.(CVE-2015-5073)

  - PCRE before 8.38 mishandles (?123) subroutine calls and
    related subroutine calls, which allows remote attackers
    to cause a denial of service (integer overflow) or
    possibly have unspecified other impact via a crafted
    regular expression, as demonstrated by a JavaScript
    RegExp object encountered by Konqueror.(CVE-2015-8387)

  - The pcre_exec function in pcre_exec.c in PCRE before
    8.38 mishandles a // pattern with a \\01 string, which
    allows remote attackers to cause a denial of service
    (heap-based buffer overflow) or possibly have
    unspecified other impact via a crafted regular
    expression, as demonstrated by a JavaScript RegExp
    object encountered by Konqueror.(CVE-2015-8380)

  - The compile_branch function in pcre_compile.c in PCRE
    8.x before 8.39 and pcre2_compile.c in PCRE2 before
    10.22 mishandles patterns containing an (*ACCEPT)
    substring in conjunction with nested parentheses, which
    allows remote attackers to execute arbitrary code or
    cause a denial of service (stack-based buffer overflow)
    via a crafted regular expression, as demonstrated by a
    JavaScript RegExp object encountered by Konqueror, aka
    ZDI-CAN-3542.(CVE-2016-3191)

  - The pcre_compile function in pcre_compile.c in PCRE
    before 8.38 mishandles certain : nesting, which allows
    remote attackers to cause a denial of service (CPU
    consumption) or possibly have unspecified other impact
    via a crafted regular expression, as demonstrated by a
    JavaScript RegExp object encountered by
    Konqueror.(CVE-2015-8391)

  - PCRE before 8.36 mishandles the
    /(((a\\2)|(a*)\\gi1/4oe-1i1/4z))*/ pattern and related
    patterns with certain internal recursive back
    references, which allows remote attackers to cause a
    denial of service (segmentation fault) or possibly have
    unspecified other impact via a crafted regular
    expression, as demonstrated by a JavaScript RegExp
    object encountered by Konqueror.(CVE-2015-2327)

  - PCRE before 8.38 mishandles the (?(i1/4oedigitsi1/4z) and
    (?(Ri1/4oedigitsi1/4z) conditions, which allows remote
    attackers to cause a denial of service (integer
    overflow) or possibly have unspecified other impact via
    a crafted regular expression, as demonstrated by a
    JavaScript RegExp object encountered by
    Konqueror.(CVE-2015-8394)

  - PCRE before 8.38 mishandles the
    /(?=di(?i1/4oe=(?1))|(?=(.))))/ pattern and related
    patterns with an unmatched closing parenthesis, which
    allows remote attackers to cause a denial of service
    (buffer overflow) or possibly have unspecified other
    impact via a crafted regular expression, as
    demonstrated by a JavaScript RegExp object encountered
    by Konqueror.(CVE-2015-8388)

  - PCRE before 8.38 mishandles the interaction of
    lookbehind assertions and mutually recursive
    subpatterns, which allows remote attackers to cause a
    denial of service (buffer overflow) or possibly have
    unspecified other impact via a crafted regular
    expression, as demonstrated by a JavaScript RegExp
    object encountered by Konqueror.(CVE-2015-8386)

  - PCRE 7.8 and 8.32 through 8.37, and PCRE2 10.10
    mishandle group empty matches, which might allow remote
    attackers to cause a denial of service (stack-based
    buffer overflow) via a crafted regular expression, as
    demonstrated by
    /^(?:(?(1)\\\\.|(^\\\\\\\\W_)?)+)+$/.(CVE-2015-3217)

  - PCRE before 8.38 mishandles the /(?|(\\k'Pm')|(?'Pm'))/
    pattern and related patterns with certain forward
    references, which allows remote attackers to cause a
    denial of service (buffer overflow) or possibly have
    unspecified other impact via a crafted regular
    expression, as demonstrated by a JavaScript RegExp
    object encountered by Konqueror.(CVE-2015-8385)

  - A flaw was found in the way PCRE handled certain
    malformed regular expressions. This issue could cause
    an application (for example, Konqueror) linked against
    PCRE to crash while parsing malicious regular
    expressions.(CVE-2014-8964)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1558
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79482695");
  script_set_attribute(attribute:"solution", value:
"Update the affected pcre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pcre-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["pcre-8.32-17.h7.eulerosv2r7",
        "pcre-devel-8.32-17.h7.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcre");
}
