#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149140);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/04");

  script_cve_id(
    "CVE-2016-3706",
    "CVE-2016-6323",
    "CVE-2017-12133",
    "CVE-2019-1010023",
    "CVE-2019-25013",
    "CVE-2020-27618",
    "CVE-2021-3326"
  );

  script_name(english:"EulerOS 2.0 SP3 : glibc (EulerOS-SA-2021-1790)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - GNU Libc current is affected by: Re-mapping current
    loaded library with malicious ELF file. The impact is:
    In worst case attacker may evaluate privileges. The
    component is: libld. The attack vector is: Attacker
    sends 2 ELF files to victim and asks to run ldd on it.
    ldd execute code. NOTE: Upstream comments indicate
    'this is being treated as a non-security bug and no
    real threat.'(CVE-2019-1010023)

  - Stack-based buffer overflow in the getaddrinfo function
    in sysdeps/posix/getaddrinfo.c in the GNU C Library
    (aka glibc or libc6) allows remote attackers to cause a
    denial of service (crash) via vectors involving hostent
    conversion. NOTE: this vulnerability exists because of
    an incomplete fix for CVE-2013-4458.(CVE-2016-3706)

  - The iconv feature in the GNU C Library (aka glibc or
    libc6) through 2.32, when processing invalid multi-byte
    input sequences in the EUC-KR encoding, may have a
    buffer over-read.(CVE-2019-25013)

  - The iconv function in the GNU C Library (aka glibc or
    libc6) 2.32 and earlier, when processing invalid input
    sequences in the ISO-2022-JP-3 encoding, fails an
    assertion in the code path and aborts the program,
    potentially resulting in a denial of
    service.(CVE-2021-3326)

  - The iconv function in the GNU C Library (aka glibc or
    libc6) 2.32 and earlier, when processing invalid
    multi-byte input sequences in IBM1364, IBM1371,
    IBM1388, IBM1390, and IBM1399 encodings, fails to
    advance the input state, which could lead to an
    infinite loop in applications, resulting in a denial of
    service, a different vulnerability from
    CVE-2016-10228.(CVE-2020-27618)

  - The makecontext function in the GNU C Library (aka
    glibc or libc6) before 2.25 creates execution contexts
    incompatible with the unwinder on ARM EABI (32-bit)
    platforms, which might allow context-dependent
    attackers to cause a denial of service (hang), as
    demonstrated by applications compiled using gccgo,
    related to backtrace generation.(CVE-2016-6323)

  - Use-after-free vulnerability in the clntudp_call
    function in sunrpc/clnt_udp.c in the GNU C Library (aka
    glibc or libc6) before 2.26 allows remote attackers to
    have unspecified impact via vectors related to error
    path.(CVE-2017-12133)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1790
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e4aca35");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1010023");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["glibc-2.17-196.h45",
        "glibc-common-2.17-196.h45",
        "glibc-devel-2.17-196.h45",
        "glibc-headers-2.17-196.h45",
        "glibc-static-2.17-196.h45",
        "glibc-utils-2.17-196.h45",
        "nscd-2.17-196.h45"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
