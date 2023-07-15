#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152327);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/11");

  script_cve_id(
    "CVE-2021-29155",
    "CVE-2021-31829",
    "CVE-2021-31916",
    "CVE-2021-33033",
    "CVE-2021-33200"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2021-2301)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - kernel/bpf/verifier.c in the Linux kernel through
    5.12.1 performs undesirable speculative loads, leading
    to disclosure of stack content via side-channel
    attacks, aka CID-801c6058d14a. The specific concern is
    not protecting the BPF stack area against speculative
    loads. Also, the BPF stack can contain uninitialized
    data that might represent sensitive information
    previously operated on by the kernel.(CVE-2021-31829)

  - The Linux kernel before 5.11.14 has a use-after-free in
    cipso_v4_genopt in net/ipv4/cipso_ipv4.c because the
    CIPSO and CALIPSO refcounting for the DOI definitions
    is mishandled, aka CID-ad5d07f4a9cd. This leads to
    writing an arbitrary value.(CVE-2021-33033)

  - kernel/bpf/verifier.c in the Linux kernel through
    5.12.7 enforces incorrect limits for pointer arithmetic
    operations, aka CID-bb01a1bba579. This can be abused to
    perform out-of-bounds reads and writes in kernel
    memory, leading to local privilege escalation to root.
    In particular, there is a corner case where the off reg
    causes a masking direction change, which then results
    in an incorrect final aux->alu_limit.(CVE-2021-33200)

  - An out-of-bounds (OOB) memory write flaw was found in
    list_devices in drivers/md/dm-ioctl.c in the
    Multi-device driver module in the Linux kernel before
    5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access
    to out-of-bounds memory leading to a system crash or a
    leak of internal kernel information. The highest threat
    from this vulnerability is to system
    availability.(CVE-2021-31916)

  - An issue was discovered in the Linux kernel through
    5.11.x. kernel/bpf/verifier.c performs undesirable
    out-of-bounds speculation on pointer arithmetic,
    leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from
    kernel memory. Specifically, for sequences of pointer
    arithmetic operations, the pointer modification
    performed by the first operation is not correctly
    accounted for when restricting subsequent
    operations.(CVE-2021-29155)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2301
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd8f418c");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h1046.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
