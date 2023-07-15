#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125004);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2012-4424",
    "CVE-2013-0242",
    "CVE-2013-2207",
    "CVE-2013-4332",
    "CVE-2013-4458",
    "CVE-2014-8121",
    "CVE-2015-0235",
    "CVE-2015-1473",
    "CVE-2015-5180",
    "CVE-2015-7547",
    "CVE-2015-8777",
    "CVE-2015-8778",
    "CVE-2015-8779",
    "CVE-2016-3706",
    "CVE-2017-12132",
    "CVE-2017-15804",
    "CVE-2017-1000366",
    "CVE-2018-6485",
    "CVE-2018-11236",
    "CVE-2018-1000001"
  );
  script_bugtraq_id(
    55543,
    57638,
    61960,
    62324,
    63299,
    72325,
    72499,
    73038
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : glibc (EulerOS-SA-2019-1551)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - stdlib/canonicalize.c in the GNU C Library (aka glibc
    or libc6) 2.27 and earlier, when processing very long
    pathname arguments to the realpath function, could
    encounter an integer overflow on 32-bit architectures,
    leading to a stack-based buffer overflow and,
    potentially, arbitrary code execution.(CVE-2018-11236)

  - An integer overflow vulnerability was found in
    hcreate() and hcreate_r() functions which could result
    in an out-of-bounds memory access. This could lead to
    application crash or, potentially, arbitrary code
    execution.(CVE-2015-8778)

  - A stack-based buffer overflow was found in the way the
    libresolv library performed dual A/AAAA DNS queries. A
    remote attacker could create a specially crafted DNS
    response which could cause libresolv to crash or,
    potentially, execute code with the permissions of the
    user running the library. Note: this issue is only
    exposed when libresolv is called from the nss_dns NSS
    service module.(CVE-2015-7547)

  - A flaw was found in the regular expression matching
    routines that process multibyte character input. If an
    application utilized the glibc regular expression
    matching mechanism, an attacker could provide
    specially-crafted input that, when processed, would
    cause the application to crash.(CVE-2013-0242)

  - A flaw was found in the way memory was being allocated
    on the stack for user space binaries. If heap (or
    different memory region) and stack memory regions were
    adjacent to each other, an attacker could use this flaw
    to jump over the stack guard gap, cause controlled
    memory corruption on process stack or the adjacent
    memory region, and thus increase their privileges on
    the system. This is glibc-side mitigation which blocks
    processing of LD_LIBRARY_PATH for programs running in
    secure-execution mode and reduces the number of
    allocations performed by the processing of LD_AUDIT,
    LD_PRELOAD, and LD_HWCAP_MASK, making successful
    exploitation of this issue more
    difficult.(CVE-2017-1000366)

  - The DNS stub resolver in the GNU C Library (aka glibc
    or libc6) before version 2.26, when EDNS support is
    enabled, will solicit large UDP responses from name
    servers, potentially simplifying off-path DNS spoofing
    attacks due to IP fragmentation.(CVE-2017-12132)

  - It was found that the files back end of Name Service
    Switch (NSS) did not isolate iteration over an entire
    database from key-based look-up API calls. An
    application performing look-ups on a database while
    iterating over it could enter an infinite loop, leading
    to a denial of service.(CVE-2014-8121)

  - Stack-based buffer overflow in the getaddrinfo function
    in sysdeps/posix/getaddrinfo.c in the GNU C Library
    (aka glibc or libc6) allows remote attackers to cause a
    denial of service (crash) via vectors involving hostent
    conversion. NOTE: this vulnerability exists because of
    an incomplete fix for CVE-2013-4458.(CVE-2016-3706)

  - In glibc 2.26 and earlier there is confusion in the
    usage of getcwd() by realpath() which can be used to
    write before the destination buffer leading to a buffer
    underflow and potential code
    execution.(CVE-2018-1000001)

  - Stack-based buffer overflow in string/strcoll_l.c in
    the GNU C Library (aka glibc or libc6) 2.17 and earlier
    allows context-dependent attackers to cause a denial of
    service (crash) or possibly execute arbitrary code via
    a long string that triggers a malloc failure and use of
    the alloca function.(CVE-2012-4424)

  - It was found that the dynamic loader did not sanitize
    the LD_POINTER_GUARD environment variable. An attacker
    could use this flaw to bypass the pointer guarding
    protection on set-user-ID or set-group-ID programs to
    execute arbitrary code with the permissions of the user
    running the application.(CVE-2015-8777)

  - The glob function in glob.c in the GNU C Library (aka
    glibc or libc6) before 2.27 contains a buffer overflow
    during unescaping of user names with the ~
    operator.(CVE-2017-15804)

  - res_query in libresolv in glibc before 2.25 allows
    remote attackers to cause a denial of service (NULL
    pointer dereference and process crash).(CVE-2015-5180)

  - pt_chown in GNU C Library (aka glibc or libc6) before
    2.18 does not properly check permissions for tty files,
    which allows local users to change the permission on
    the files and obtain access to arbitrary
    pseudo-terminals by leveraging a FUSE file
    system.(CVE-2013-2207)

  - A stack overflow flaw was found in glibc's swscanf()
    function. An attacker able to make an application call
    the swscanf() function could use this flaw to crash
    that application or, potentially, execute arbitrary
    code with the permissions of the user running the
    application.(CVE-2015-1473)

  - It was found that getaddrinfo() did not limit the
    amount of stack memory used during name resolution. An
    attacker able to make an application resolve an
    attacker-controlled hostname or IP address could
    possibly cause the application to exhaust all stack
    memory and crash.(CVE-2013-4458)

  - A heap-based buffer overflow was found in glibc's
    __nss_hostname_digits_dots() function, which is used by
    the gethostbyname() and gethostbyname2() glibc function
    calls. A remote attacker able to make an application
    call either of these functions could use this flaw to
    execute arbitrary code with the permissions of the user
    running the application.(CVE-2015-0235)

  - Multiple integer overflow flaws, leading to heap-based
    buffer overflows, were found in glibc's memory
    allocator functions (pvalloc, valloc, and memalign). If
    an application used such a function, it could cause the
    application to crash or, potentially, execute arbitrary
    code with the privileges of the user running the
    application.(CVE-2013-4332)

  - An integer overflow in the implementation of the
    posix_memalign in memalign functions in the GNU C
    Library (aka glibc or libc6) 2.26 and earlier could
    cause these functions to return a pointer to a heap
    area that is too small, potentially leading to heap
    corruption.(CVE-2018-6485)

  - A stack based buffer overflow vulnerability was found
    in the catopen() function. An excessively long string
    passed to the function could cause it to crash or,
    potentially, execute arbitrary code.(CVE-2015-8779)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1551
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97fa15c6");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0235");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6485");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc realpath() Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
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

pkgs = ["glibc-2.17-222.h11",
        "glibc-common-2.17-222.h11",
        "glibc-devel-2.17-222.h11",
        "glibc-headers-2.17-222.h11",
        "nscd-2.17-222.h11"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
