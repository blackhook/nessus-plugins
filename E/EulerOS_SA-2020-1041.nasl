#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132795);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-10739",
    "CVE-2019-19126",
    "CVE-2019-6488"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.5.0 : glibc (EulerOS-SA-2020-1041)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - In the GNU C Library (aka glibc or libc6) through 2.28,
    the getaddrinfo function would successfully parse a
    string that contained an IPv4 address followed by
    whitespace and arbitrary characters, which could lead
    applications to incorrectly assume that it had parsed a
    valid string, without the possibility of embedded HTTP
    headers or other potentially dangerous
    substrings.(CVE-2016-10739)

  - On the x86-64 architecture, the GNU C Library (aka
    glibc) before 2.31 fails to ignore the
    LD_PREFER_MAP_32BIT_EXEC environment variable during
    program execution after a security transition, allowing
    local attackers to restrict the possible mapping
    addresses for loaded libraries and thus bypass ASLR for
    a setuid program.(CVE-2019-19126)

  - The string component in the GNU C Library (aka glibc or
    libc6) through 2.28, when running on the x32
    architecture, incorrectly attempts to use a 64-bit
    register for size_t in assembly codes, which can lead
    to a segmentation fault or possibly unspecified other
    impact, as demonstrated by a crash in
    __memmove_avx_unaligned_erms in
    sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S
    during a memcpy.(CVE-2019-6488)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1041
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?206e2b8e");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6488");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.5.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.5.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["glibc-2.28-9.h29.eulerosv2r8",
        "glibc-all-langpacks-2.28-9.h29.eulerosv2r8",
        "glibc-common-2.28-9.h29.eulerosv2r8",
        "glibc-devel-2.28-9.h29.eulerosv2r8",
        "glibc-headers-2.28-9.h29.eulerosv2r8",
        "libnsl-2.28-9.h29.eulerosv2r8",
        "nscd-2.28-9.h29.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
