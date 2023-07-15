#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2337.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145345);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/18");

  script_cve_id("CVE-2020-29367");

  script_name(english:"openSUSE Security Update : blosc (openSUSE-2020-2337)");
  script_summary(english:"Check for the openSUSE-2020-2337 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for blosc fixes the following issues :

Update to version 1.20.1 boo#1179914 CVE-2020-29367 :

  - More saftey checks have been implemented so that
    potential flaws discovered by new fuzzers in OSS-Fuzzer
    are fixed now

  - BloscLZ updated to 2.3.0. Expect better compression
    ratios for faster codecs. For details, see our new blog
    post: https://blosc.org/posts/beast-release/

  - Fixed the _xgetbv() collision. Thanks to Micha&#x142;
    G&oacute;rny (@mgorny).

Update to version 1.19.0 :

  - The length of automatic blocksizes for fast codecs (lz4,
    blosclz) has been incremented quite a bit (up to 256 KB)
    for better compression ratios.

  - The performance in modern CPUs (with at least 256 KB in
    L2 cache) should be better too (for older CPUs the
    performance should stay roughly the same).

  - For small buffers that cannot be compressed (typically <
    128 bytes), blosc_compress() returns now a 0 (cannot
    compress) instead of a negative number (internal error).
    See #294.

  - blosclz codec updated to 2.1.0. Expect better
    compression ratios and performance in a wider variety of
    scenarios.

  - blosc_decompress_unsafe(), blosc_decompress_ctx_unsafe()
    and blosc_getitem_unsafe() have been removed because
    they are dangerous and after latest improvements, they
    should not be used in production.

Update to version 1.18.1 :

  - Fixed the copy of the leftovers of a chunk when its size
    is not a multiple of the typesize.

Update to version 1.17.1 :

  - BloscLZ codec updated to 2.0.0.

Update to version 1.16.3 :

  - Fix for building for clang with -march=haswell. See PR
    #262.

  - Fix all the known warnings for GCC/Clang. Still some
    work to do for MSVC in this front.

  - Due to some problems with several CI systems, the check
    for library symbols are deactivated now by default. If
    you want to enforce this check, use: cmake ..
    -DDEACTIVATE_SYMBOLS_CHECK=ON to re-activate it.

  - Correct the check for the compressed size when the
    buffer is memcpyed. This was a regression introduced in
    1.16.0. Fixes #261.

  - Fixed a regression in 1.16.0 that prevented to compress
    empty buffers (see #260).

  - Now the functions that execute Blosc decompressions are
    safe by default for untrusted/possibly corrupted inputs.

  - The previous functions (with less safety) checks are
    still available with a '_unsafe' suffix. The complete
    list is :

  - Also, a new API function named blosc_cbuffer_validate(),
    for validating Blosc compressed data, has been added.

  - For details, see PR #258. Thanks to Jeremy
    Maitin-Shepard.

  - Fixed a bug in blosc_compress() that could lead to
    thread deadlock under some situations. See #251. Thanks
    to @wenjuno for the report and the fix.

  - Fix data race in shuffle.c host_implementation
    initialization. Fixes #253. Thanks to Jeremy
    Maitin-Shepard.

  - Add workaround for Visual Studio 2008's lack of a
    stdint.h file to blosclz.c.

  - Replaced //-comments with /**/-comments and other
    improvements for compatibility with quite old gcc
    compilers. See PR #243. Thanks to Andreas Martin.

  - Empty buffers can be compressed again (this was
    unadvertedly prevented while fixing #234). See #247.
    Thanks to Valentin Haenel.

Update to version 1.14.4 :

  - Added a new DEACTIVATE_SSE2 option for cmake that is
    useful for disabling SSE2 when doing cross-compilation
    (see #236).

  - New check for detecting output buffers smaller than
    BLOSC_MAX_OVERHEAD.

  - The complib and version parameters for
    blosc_get_complib_info() can be safely set to NULL now.
    This allows to call this function even if the user is
    not interested in these parameters (so no need to
    reserve memory for them).

  - In some situations that a supposedly blosc chunk is
    passed to blosc_decompress(), one might end with an
    Arithmetic exception. This is probably due to the chunk
    not being an actual blosc chunk, and divisions by zero
    might occur. A protection has been added for this.

Update to version 1.14.3 :

  - Fixed a bug that caused C-Blosc to crash on platforms
    requiring strict alignment.

  - Fixed a piece of code that was not C89 compliant."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blosc.org/posts/beast-release/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179914"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected blosc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:blosc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:blosc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblosc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblosc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"blosc-debugsource-1.20.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"blosc-devel-1.20.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libblosc1-1.20.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libblosc1-debuginfo-1.20.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"blosc-debugsource-1.20.1-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"blosc-devel-1.20.1-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libblosc1-1.20.1-lp152.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libblosc1-debuginfo-1.20.1-lp152.4.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "blosc-debugsource / blosc-devel / libblosc1 / libblosc1-debuginfo");
}
