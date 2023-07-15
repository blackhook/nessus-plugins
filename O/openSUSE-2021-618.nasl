#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-618.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149589);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-21372", "CVE-2021-21373", "CVE-2021-21374");

  script_name(english:"openSUSE Security Update : nim (openSUSE-2021-618)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for nim fixes the following issues :

num was updated to version 1.2.12 :

  - Fixed GC crash resulting from inlining of the memory
    allocation procs

  - Fixed &ldquo;incorrect raises effect for
    $(NimNode)&rdquo; (#17454)

From version 1.2.10 :

  - Fixed &ldquo;JS backend doesn&rsquo;t handle float->int
    type conversion &ldquo; (#8404)

  - Fixed &ldquo;The &ldquo;try except&rdquo; not work when
    the &ldquo;OSError: Too many open files&rdquo; error
    occurs!&rdquo; (#15925)

  - Fixed &ldquo;Nim emits #line 0 C preprocessor directives
    with &ndash;debugger:native, with ICE in gcc-10&rdquo;
    (#15942)

  - Fixed &ldquo;tfuturevar fails when activated&rdquo;
    (#9695)

  - Fixed &ldquo;nre.escapeRe is not gcsafe&rdquo; (#16103)

  - Fixed &ldquo;&ldquo;Error: internal error:
    genRecordFieldAux&rdquo; - in the
    &ldquo;version-1-4&rdquo; branch&rdquo; (#16069)

  - Fixed &ldquo;-d:fulldebug switch does not compile with
    gc:arc&rdquo; (#16214)

  - Fixed &ldquo;osLastError may randomly raise defect and
    crash&rdquo; (#16359)

  - Fixed &ldquo;generic importc proc&rsquo;s don&rsquo;t
    work (breaking lots of vmops procs for js)&rdquo;
    (#16428)

  - Fixed &ldquo;Concept: codegen ignores parameter
    passing&rdquo; (#16897)

  - Fixed &ldquo;(.push exportc.) interacts with anonymous
    functions&rdquo; (#16967)

  - Fixed &ldquo;memory allocation during (.global.) init
    breaks GC&rdquo; (#17085)

  - Fixed 'Nimble arbitrary code execution for specially
    crafted package metadata'

  +
    https://github.com/nim-lang/security/security/advisories
    /GHSA-rg9f-w24h-962p

  + (boo#1185083, CVE-2021-21372)

  - Fixed 'Nimble falls back to insecure http url when
    fetching packages'

  +
    https://github.com/nim-lang/security/security/advisories
    /GHSA-8w52-r35x-rgp8

  + (boo#1185084, CVE-2021-21373)

  - Fixed 'Nimble fails to validate certificates due to
    insecure httpClient defaults'

  +
    https://github.com/nim-lang/security/security/advisories
    /GHSA-c2wm-v66h-xhxx

  + (boo#1185085, CVE-2021-21374)

from version 1.2.8

  - Fixed &ldquo;Defer and &ndash;gc:arc&rdquo; (#15071)

  - Fixed &ldquo;Issue with &ndash;gc:arc at compile
    time&rdquo; (#15129)

  - Fixed &ldquo;Nil check on each field fails in generic
    function&rdquo; (#15101)

  - Fixed &ldquo;[strscans] scanf doesn&rsquo;t match a
    single character with $+ if it&rsquo;s the end of the
    string&rdquo; (#15064)

  - Fixed &ldquo;Crash and incorrect return values when
    using readPasswordFromStdin on Windows.&rdquo; (#15207)

  - Fixed &ldquo;Inconsistent unsigned -> signed RangeDefect
    usage across integer sizes&rdquo; (#15210)

  - Fixed &ldquo;toHex results in RangeDefect exception when
    used with large uint64&rdquo; (#15257)

  - Fixed &ldquo;Mixing &lsquo;return&rsquo; with
    expressions is allowed in 1.2&rdquo; (#15280)

  - Fixed &ldquo;proc execCmdEx doesn&rsquo;t work with
    -d:useWinAnsi&rdquo; (#14203)

  - Fixed &ldquo;memory corruption in tmarshall.nim&rdquo;
    (#9754)

  - Fixed &ldquo;Wrong number of variables&rdquo; (#15360)

  - Fixed &ldquo;defer doesnt work with block, break and
    await&rdquo; (#15243)

  - Fixed &ldquo;Sizeof of case object is incorrect.
    Showstopper&rdquo; (#15516)

  - Fixed &ldquo;Mixing &lsquo;return&rsquo; with
    expressions is allowed in 1.2&rdquo; (#15280)

  - Fixed &ldquo;regression(1.0.2 => 1.0.4) VM register
    messed up depending on unrelated context&rdquo; (#15704)

from version 1.2.6

  - Fixed &ldquo;The pegs module doesn&rsquo;t work with
    generics!&rdquo; (#14718)

  - Fixed &ldquo;[goto exceptions] (.noReturn.) pragma is
    not detected in a case expression&rdquo; (#14458)

  - Fixed &ldquo;[exceptions:goto] C compiler error with
    dynlib pragma calling a proc&rdquo; (#14240)

  - Fixed &ldquo;Nim source archive install:
    &lsquo;install.sh&rsquo; fails with error: cp: cannot
    stat &lsquo;bin/nim-gdb&rsquo;: No such file or
    directory&rdquo; (#14748)

  - Fixed &ldquo;Stropped identifiers don&rsquo;t work as
    field names in tuple literals&rdquo; (#14911)

  - Fixed &ldquo;uri.decodeUrl crashes on incorrectly
    formatted input&rdquo; (#14082)

  - Fixed &ldquo;odbcsql module has some wrong integer
    types&rdquo; (#9771)

  - Fixed &ldquo;[ARC] Compiler crash declaring a finalizer
    proc directly in &lsquo;new&rsquo;&rdquo; (#15044)

  - Fixed &ldquo;code with named arguments in proc of
    winim/com can not been compiled&rdquo; (#15056)

  - Fixed &ldquo;javascript backend produces JavaScript code
    with syntax error in object syntax&rdquo; (#14534)

  - Fixed &ldquo;[ARC] SIGSEGV when calling a closure as a
    tuple field in a seq&rdquo; (#15038)

  - Fixed &ldquo;Compiler crashes when using string as
    object variant selector with else branch&rdquo; (#14189)

  - Fixed &ldquo;Constructing a uint64 range on a 32-bit
    machine leads to incorrect codegen&rdquo; (#14616)

Update to version 1.2.2 :

  - See https://nim-lang.org/blog.html for details

Update to version 1.0.2 :

  - See https://nim-lang.org/blog.html for details");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185085");
  # https://github.com/nim-lang/security/security/advisories/GHSA-8w52-r35x-rgp8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8e0330b");
  # https://github.com/nim-lang/security/security/advisories/GHSA-c2wm-v66h-xhxx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0791b363");
  # https://github.com/nim-lang/security/security/advisories/GHSA-rg9f-w24h-962p
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d0b1bba");
  script_set_attribute(attribute:"see_also", value:"https://nim-lang.org/blog.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected nim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21374");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"nim-1.2.12-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nim-debuginfo-1.2.12-lp152.2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nim / nim-debuginfo");
}
