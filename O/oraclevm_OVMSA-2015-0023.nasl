#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0023.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81118);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0296", "CVE-2010-0830", "CVE-2010-3847", "CVE-2010-3856", "CVE-2011-0536", "CVE-2011-1071", "CVE-2011-1089", "CVE-2011-1095", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4332", "CVE-2014-0475", "CVE-2014-5119", "CVE-2015-0235");
  script_bugtraq_id(40063, 44154, 44347, 46563, 46740, 47370, 57638, 58839, 62324, 64465, 68505, 68983, 69738, 72325);

  script_name(english:"OracleVM 3.2 : glibc (OVMSA-2015-0023) (GHOST)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Switch to use malloc when the input line is too long
    [Orabug 19951108]

  - Use a /sys/devices/system/cpu/online for
    _SC_NPROCESSORS_ONLN implementation [Orabug 17642251]
    (Joe Jin)

  - Fix parsing of numeric hosts in gethostbyname_r
    (CVE-2015-0235, #1183532).

  - Remove gconv transliteration loadable modules support
    (CVE-2014-5119, - _nl_find_locale: Improve handling of
    crafted locale names (CVE-2014-0475, 

  - Fix patch for integer overflows in *valloc and memalign.
    (CVE-2013-4332, #1011805).

  - Fix return code when starting an already started nscd
    daemon (#979413).

  - Fix getnameinfo for many PTR record queries (#1020486).

  - Return EINVAL error for negative sizees to getgroups
    (#995207).

  - Fix integer overflows in *valloc and memalign.
    (CVE-2013-4332, #1011805).

  - Add support for newer L3 caches on x86-64 and correctly
    count the number of hardware threads sharing a cacheline
    (#1003420).

  - Revert incomplete fix for bug #758193.

  - Fix _nl_find_msg malloc failure case, and callers
    (#957089).

  - Test on init_fct, not result->__init_fct, after
    demangling (#816647).

  - Don't handle ttl == 0 specially (#929035).

  - Fix multibyte character processing crash in regexp
    (CVE-2013-0242, #951132)

  - Fix getaddrinfo stack overflow resulting in application
    crash (CVE-2013-1914, #951132)

  - Add missing patch to avoid use after free (#816647)

  - Fix race in initgroups compat_call (#706571)

  - Fix return value from getaddrinfo when servers are down.
    (#758193)

  - Fix fseek on wide character streams. Sync's seeking code
    with RHEL 6 (#835828)

  - Call feraiseexcept only if exceptions are not masked
    (#861871).

  - Always demangle function before checking for NULL value.
    (#816647).

  - Do not fail in ttyname if /proc is not available
    (#851450).

  - Fix errno for various overflow situations in vfprintf.
    Add missing overflow checks. (#857387)

  - Handle failure of _nl_explode_name in all cases
    (#848481)

  - Define the default fuzz factor to 2 to make it easier to
    manipulate RHEL 5 RPMs on RHEL 6 and newer systems.

  - Fix race in intl/* testsuite (#849202)

  - Fix out of bounds array access in strto* exposed by
    847930 patch.

  - Really fix POWER4 strncmp crash (#766832).

  - Fix integer overflow leading to buffer overflow in
    strto* (#847930)

  - Fix race in msort/qsort (#843672)

  - Fix regression due to 797096 changes (#845952)

  - Do not use PT_IEEE_IP ptrace calls (#839572)

  - Update ULPs (#837852)

  - Fix various transcendentals in non-default rounding
    modes (#837852)

  - Fix unbound alloca in vfprintf (#826947)

  - Fix iconv segfault if the invalid multibyte character
    0xffff is input when converting from IBM930. (#823905)

  - Fix fnmatch when '*' wildcard is applied on a file name
    containing multibyte chars. (#819430)

  - Fix unbound allocas use in glob_in_dir, getaddrinfo and
    others. (#797096)

  - Fix segfault when running ld.so --verify on some DSO's
    in current working directory. (#808342)

  - Incorrect initialization order for dynamic loader
    (#813348)

  - Fix return code when stopping already stopped nscd
    daemon (#678227)

  - Remove MAP_32BIT for pthread stack mappings, use
    MAP_STACK instead (#641094)

  - Fix setuid vs sighandler_setxid race (#769852)

  - Fix access after end of search string in regex matcher
    (#757887)

  - Fix POWER4 strncmp crash (#766832)

  - Fix SC_*CACHE detection for X5670 cpus (#692182)

  - Fix parsing IPV6 entries in /etc/resolv.conf (#703239)

  - Fix double-free in nss_nis code (#500767)

  - Add kernel VDSO support for s390x (#795896)

  - Fix race in malloc arena creation and make
    implementation match documented behaviour (#800240)

  - Do not override TTL of CNAME with TTL of its alias
    (#808014)

  - Fix short month names in fi_FI locale #(657266).

  - Fix nscd crash for group with large number of members
    (#788989)

  - Fix Slovakia currency (#799853)

  - Fix getent malloc failure check (#806403)

  - Fix short month names in zh_CN locale (#657588)

  - Fix decimal point symbol for Portuguese currency
    (#710216)

  - Avoid integer overflow in sbrk (#767358)

  - Avoid race between [,__de]allocate_stack and
    __reclaim_stacks during fork (#738665)

  - Fix race between IO_flush_all_lockp & pthread_cancel
    (#751748)

  - Fix memory leak in NIS endgrent (#809325)

  - Allow getaddr to accept SCTP socket types in hints
    (#765710)

  - Fix errno handling in vfprintf (#794814)

  - Filter out <built-in> when building file lists
    (#784646).

  - Avoid 'nargs' integer overflow which could be used to
    bypass FORTIFY_SOURCE (#794814)

  - Fix currency_symbol for uk_UA (#639000)

  - Correct test for detecting cycle during topo sort
    (#729661)

  - Check values from TZ file header (#767688)

  - Complete the numeric settings fix (#675259)

  - Complete the change for error codes from pthread_create
    (#707998)

  - Truncate time values in Linux futimes when falling back
    to utime (#758252)

  - Update systemtaparches

  - Add rules to build libresolv with SSP flags (#756453)

  - Fix PLT reference

  - Workaround misconfigured system (#702300)

  - Update systemtaparches

  - Correct cycle detection during dependency sorting
    (#729661)

  - Add gdb hooks (#711924)

  - Fix alloca accounting in strxfm and strcoll (#585433)

  - Correct cycle detection during dependency sorting
    (#729661)

  - ldd: never run file directly (#531160)

  - Implement greedy matching of weekday and month names
    (#657570)

  - Fix incorrect numeric settings (#675259)

  - Implement new mode for NIS passwd.adjunct.byname table
    (#678318)

  - Query NIS domain only when needed (#703345)

  - Count total processors using sysfs (#706894)

  - Translate clone error if necessary (#707998)

  - Workaround kernel clobbering robust list (#711531)

  - Use correct type when casting d_tag (#599056,
    CVE-2010-0830)

  - Report write error in addmnt even for cached streams
    (#688980, CVE-2011-1089)

  - Don't underestimate length of DST substitution (#694655)

  - Don't allocate executable stack when it cannot be
    allocated in the first 4G (#448011)

  - Initialize resolver state in nscd (#676039)

  - No cancel signal in unsafe places (#684808)

  - Check size of pattern in wide character representation
    in fnmatch (#681054)

  - Avoid too much stack use in fnmatch (#681054,
    CVE-2011-1071)

  - Properly quote output of locale (#625893, CVE-2011-1095)

  - Don't leave empty element in rpath when skipping the
    first element, ignore rpath elements containing
    non-isolated use of $ORIGIN when privileged (#667974,
    CVE-2011-0536)

  - Fix handling of newline in addmntent (#559579,
    CVE-2010-0296)

  - Don't ignore $ORIGIN in libraries (#670988)

  - Fix false assertion (#604796)

  - Fix ordering of DSO constructors and destructors
    (#604796)

  - Fix typo (#531576)

  - Fix concurrency problem between dl_open and
    dl_iterate_phdr (#649956)

  - Require suid bit on audit objects in privileged programs
    (#645678, CVE-2010-3856)

  - Never expand $ORIGIN in privileged programs (#643819,
    CVE-2010-3847)

  - Add timestamps to nscd logs (#527558)

  - Fix index wraparound handling in memusage (#531576)

  - Handle running out of buffer space with IPv6 mapping
    enabled (#533367)

  - Don't deadlock in __dl_iterate_phdr while (un)loading
    objects (#549813)

  - Avoid alloca in setenv for long strings (#559974)

  - Recognize POWER7 and ISA 2.06 (#563563)

  - Add support for AT_BASE_PLATFORM (#563599)

  - Restore locking in free_check (#585674)

  - Fix lookup of collation sequence value during regexp
    matching (#587360)

  - Fix POWER6 memcpy/memset (#579011)

  - Fix scope handling during dl_close (#593675)

  - Enable -fasynchronous-unwind-tables throughout (#593047)

  - Fix crash when aio thread creation fails (#566712)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-January/000260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acafac78"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc / glibc-common / nscd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"glibc-2.5-123.0.1.el5_11.1")) flag++;
if (rpm_check(release:"OVS3.2", reference:"glibc-common-2.5-123.0.1.el5_11.1")) flag++;
if (rpm_check(release:"OVS3.2", reference:"nscd-2.5-123.0.1.el5_11.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / nscd");
}
