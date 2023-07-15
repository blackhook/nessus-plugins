#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(139997);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : perl (EulerOS-SA-2020-1894)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the perl packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - regcomp.c in Perl before 5.30.3 allows a buffer
    overflow via a crafted regular expression because of
    recursive S_study_chunk calls.(CVE-2020-12723)

  - Perl before 5.30.3 has an integer overflow related to
    mishandling of a 'PL_regkind[OP(n)] == NOTHING'
    situation. A crafted regular expression could lead to
    malformed bytecode with a possibility of instruction
    injection.(CVE-2020-10878)

  - Perl before 5.30.3 on 32-bit platforms allows a
    heap-based buffer overflow because nested regular
    expression quantifiers have an integer
    overflow.(CVE-2020-10543)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1894
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5aac20b1");
  script_set_attribute(attribute:"solution", value:
"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Net-Ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perl-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["perl-5.28.0-423.h7.eulerosv2r8",
        "perl-Attribute-Handlers-1.01-423.h7.eulerosv2r8",
        "perl-Devel-Peek-1.27-423.h7.eulerosv2r8",
        "perl-Devel-SelfStubber-1.06-423.h7.eulerosv2r8",
        "perl-Errno-1.29-423.h7.eulerosv2r8",
        "perl-ExtUtils-Embed-1.35-423.h7.eulerosv2r8",
        "perl-ExtUtils-Miniperl-1.08-423.h7.eulerosv2r8",
        "perl-IO-1.39-423.h7.eulerosv2r8",
        "perl-IO-Zlib-1.10-423.h7.eulerosv2r8",
        "perl-Locale-Maketext-Simple-0.21-423.h7.eulerosv2r8",
        "perl-Math-Complex-1.59-423.h7.eulerosv2r8",
        "perl-Memoize-1.03-423.h7.eulerosv2r8",
        "perl-Module-Loaded-0.08-423.h7.eulerosv2r8",
        "perl-Net-Ping-2.62-423.h7.eulerosv2r8",
        "perl-Pod-Html-1.24-423.h7.eulerosv2r8",
        "perl-SelfLoader-1.25-423.h7.eulerosv2r8",
        "perl-Test-1.31-423.h7.eulerosv2r8",
        "perl-Time-Piece-1.33-423.h7.eulerosv2r8",
        "perl-devel-5.28.0-423.h7.eulerosv2r8",
        "perl-interpreter-5.28.0-423.h7.eulerosv2r8",
        "perl-libnetcfg-5.28.0-423.h7.eulerosv2r8",
        "perl-libs-5.28.0-423.h7.eulerosv2r8",
        "perl-macros-5.28.0-423.h7.eulerosv2r8",
        "perl-open-1.11-423.h7.eulerosv2r8",
        "perl-utils-5.28.0-423.h7.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
