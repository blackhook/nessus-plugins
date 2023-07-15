#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127029);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2019-11477",
    "CVE-2019-11478",
    "CVE-2019-11479",
    "CVE-2019-12817"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2019-1792)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The kernel package contains the Linux kernel (vmlinuz),
    the core of any Linux operating system. The kernel
    handles the basic functions of the operating system:
    memory allocation, process allocation, device input and
    output, etc.Security Fix(es):An integer overflow flaw
    was found in the way the Linux kernel's networking
    subsystem processed TCP Selective Acknowledgment (SACK)
    segments. While processing SACK segments, the Linux
    kernel's socket buffer (SKB) data structure becomes
    fragmented. Each fragment is about TCP maximum segment
    size (MSS) bytes. To efficiently process SACK blocks,
    the Linux kernel merges multiple fragmented SKBs into
    one, potentially overflowing the variable holding the
    number of segments. A remote attacker could use this
    flaw to crash the Linux kernel by sending a crafted
    sequence of SACK segments on a TCP connection with
    small value of TCP MSS, resulting in a denial of
    service (DoS). (CVE-2019-11477)Kernel: tcp: excessive
    resource consumption while processing SACK blocks
    allows remote denial of service (CVE-2019-11478)Kernel:
    tcp: excessive resource consumption for TCP connections
    with low MSS allows remote denial of service
    (CVE-2019-11479)A flaw was found in the way the Linux
    kernel's memory subsystem on certain 64-bit PowerPCs
    with the hash page table MMU handled memory above
    512TB. A local, unprivileged user could use this flaw
    to escalate their privileges on the
    system.(CVE-2019-12817)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1792
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e70bdf42");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12817");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["kernel-4.19.36-vhulk1906.3.0.h356.eulerosv2r8",
        "kernel-debuginfo-4.19.36-vhulk1906.3.0.h356.eulerosv2r8",
        "kernel-debuginfo-common-aarch64-4.19.36-vhulk1906.3.0.h356.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1906.3.0.h356.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1906.3.0.h356.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1906.3.0.h356.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1906.3.0.h356.eulerosv2r8",
        "perf-4.19.36-vhulk1906.3.0.h356.eulerosv2r8",
        "python-perf-4.19.36-vhulk1906.3.0.h356.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
