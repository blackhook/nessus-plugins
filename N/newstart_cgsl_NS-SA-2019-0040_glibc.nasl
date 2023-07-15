#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0040. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127214);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2017-16997",
    "CVE-2018-6485",
    "CVE-2018-11236",
    "CVE-2018-11237"
  );
  script_bugtraq_id(104255);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : glibc Multiple Vulnerabilities (NS-SA-2019-0040)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has glibc packages installed that are affected by
multiple vulnerabilities:

  - An integer overflow in the implementation of the
    posix_memalign in memalign functions in the GNU C
    Library (aka glibc or libc6) 2.26 and earlier could
    cause these functions to return a pointer to a heap area
    that is too small, potentially leading to heap
    corruption. (CVE-2018-6485)

  - elf/dl-load.c in the GNU C Library (aka glibc or libc6)
    2.19 through 2.26 mishandles RPATH and RUNPATH
    containing $ORIGIN for a privileged (setuid or
    AT_SECURE) program, which allows local users to gain
    privileges via a Trojan horse library in the current
    working directory, related to the fillin_rpath and
    decompose_rpath functions. This is associated with
    misinterpretion of an empty RPATH/RUNPATH token as the
    ./ directory. NOTE: this configuration of
    RPATH/RUNPATH for a privileged program is apparently
    very uncommon; most likely, no such program is shipped
    with any common Linux distribution. (CVE-2017-16997)

  - A buffer overflow has been discovered in the GNU C
    Library (aka glibc or libc6) in the
    __mempcpy_avx512_no_vzeroupper function when particular
    conditions are met. An attacker could use this
    vulnerability to cause a denial of service or
    potentially execute code. (CVE-2018-11237)

  - stdlib/canonicalize.c in the GNU C Library (aka glibc or
    libc6) 2.27 and earlier, when processing very long
    pathname arguments to the realpath function, could
    encounter an integer overflow on 32-bit architectures,
    leading to a stack-based buffer overflow and,
    potentially, arbitrary code execution. (CVE-2018-11236)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0040");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16997");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6485");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/18");
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
    "glibc-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-common-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-debuginfo-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-debuginfo-common-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-devel-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-headers-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-i18n-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-iconv-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-lang-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-locale-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-static-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-tools-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "glibc-utils-2.17-260.el7.cgslv5.0.6.g56f1a75.lite",
    "nscd-2.17-260.el7.cgslv5.0.6.g56f1a75.lite"
  ],
  "CGSL MAIN 5.04": [
    "glibc-2.17-260.el7.cgslv5.0.1.g5ec4ae0",
    "glibc-common-2.17-260.el7.cgslv5.0.1.g5ec4ae0",
    "glibc-debuginfo-2.17-260.el7.cgslv5.0.1.g5ec4ae0",
    "glibc-debuginfo-common-2.17-260.el7.cgslv5.0.1.g5ec4ae0",
    "glibc-devel-2.17-260.el7.cgslv5.0.1.g5ec4ae0",
    "glibc-headers-2.17-260.el7.cgslv5.0.1.g5ec4ae0",
    "glibc-static-2.17-260.el7.cgslv5.0.1.g5ec4ae0",
    "glibc-utils-2.17-260.el7.cgslv5.0.1.g5ec4ae0",
    "nscd-2.17-260.el7.cgslv5.0.1.g5ec4ae0"
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
