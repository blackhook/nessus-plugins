#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0012. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127161);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/03");

  script_cve_id(
    "CVE-2010-3847",
    "CVE-2010-3856",
    "CVE-2012-4412",
    "CVE-2012-4424",
    "CVE-2013-0242",
    "CVE-2013-1914",
    "CVE-2013-2207",
    "CVE-2013-4237",
    "CVE-2013-4332",
    "CVE-2013-4458",
    "CVE-2013-4788"
  );

  script_name(english:"NewStart CGSL MAIN 5.04 : glibc Multiple Vulnerabilities (NS-SA-2019-0012)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has glibc packages installed that are affected by multiple
vulnerabilities:

  - elf/dl-load.c in ld.so in the GNU C Library (aka glibc
    or libc6) through 2.11.2, and 2.12.x through 2.12.1,
    does not properly handle a value of $ORIGIN for the
    LD_AUDIT environment variable, which allows local users
    to gain privileges via a crafted dynamic shared object
    (DSO) located in an arbitrary directory. (CVE-2010-3847)

  - ld.so in the GNU C Library (aka glibc or libc6) before
    2.11.3, and 2.12.x before 2.12.2, does not properly
    restrict use of the LD_AUDIT environment variable to
    reference dynamic shared objects (DSOs) as audit
    objects, which allows local users to gain privileges by
    leveraging an unsafe DSO located in a trusted library
    directory, as demonstrated by libpcprofile.so.
    (CVE-2010-3856)

  - Integer overflow in string/strcoll_l.c in the GNU C
    Library (aka glibc or libc6) 2.17 and earlier allows
    context-dependent attackers to cause a denial of service
    (crash) or possibly execute arbitrary code via a long
    string, which triggers a heap-based buffer overflow.
    (CVE-2012-4412)

  - Stack-based buffer overflow in string/strcoll_l.c in the
    GNU C Library (aka glibc or libc6) 2.17 and earlier
    allows context-dependent attackers to cause a denial of
    service (crash) or possibly execute arbitrary code via a
    long string that triggers a malloc failure and use of
    the alloca function. (CVE-2012-4424)

  - A flaw was found in the regular expression matching
    routines that process multibyte character input. If an
    application utilized the glibc regular expression
    matching mechanism, an attacker could provide specially-
    crafted input that, when processed, would cause the
    application to crash. (CVE-2013-0242)

  - It was found that getaddrinfo() did not limit the amount
    of stack memory used during name resolution. An attacker
    able to make an application resolve an attacker-
    controlled hostname or IP address could possibly cause
    the application to exhaust all stack memory and crash.
    (CVE-2013-1914, CVE-2013-4458)

  - pt_chown in GNU C Library (aka glibc or libc6) before
    2.18 does not properly check permissions for tty files,
    which allows local users to change the permission on the
    files and obtain access to arbitrary pseudo-terminals by
    leveraging a FUSE file system. (CVE-2013-2207)

  - An out-of-bounds write flaw was found in the way the
    glibc's readdir_r() function handled file system entries
    longer than the NAME_MAX character constant. A remote
    attacker could provide a specially crafted NTFS or CIFS
    file system that, when processed by an application using
    readdir_r(), would cause that application to crash or,
    potentially, allow the attacker to execute arbitrary
    code with the privileges of the user running the
    application. (CVE-2013-4237)

  - Multiple integer overflow flaws, leading to heap-based
    buffer overflows, were found in glibc's memory allocator
    functions (pvalloc, valloc, and memalign). If an
    application used such a function, it could cause the
    application to crash or, potentially, execute arbitrary
    code with the privileges of the user running the
    application. (CVE-2013-4332)

  - The PTR_MANGLE implementation in the GNU C Library (aka
    glibc or libc6) 2.4, 2.17, and earlier, and Embedded
    GLIBC (EGLIBC) does not initialize the random value for
    the pointer guard, which makes it easier for context-
    dependent attackers to control execution flow by
    leveraging a buffer-overflow vulnerability in an
    application and using the known zero value pointer guard
    to calculate a pointer address. (CVE-2013-4788)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0012");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4412");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc $ORIGIN Expansion Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

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

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "glibc-2.17-196.el7_4.2.cgslv5.0.1.gc83498c",
    "glibc-common-2.17-196.el7_4.2.cgslv5.0.1.gc83498c",
    "glibc-debuginfo-2.17-196.el7_4.2.cgslv5.0.1.gc83498c",
    "glibc-debuginfo-common-2.17-196.el7_4.2.cgslv5.0.1.gc83498c",
    "glibc-devel-2.17-196.el7_4.2.cgslv5.0.1.gc83498c",
    "glibc-headers-2.17-196.el7_4.2.cgslv5.0.1.gc83498c",
    "glibc-static-2.17-196.el7_4.2.cgslv5.0.1.gc83498c",
    "glibc-utils-2.17-196.el7_4.2.cgslv5.0.1.gc83498c",
    "nscd-2.17-196.el7_4.2.cgslv5.0.1.gc83498c"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
