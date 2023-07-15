#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124835);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id(
    "CVE-2015-8839",
    "CVE-2017-5754",
    "CVE-2017-13166",
    "CVE-2017-13305",
    "CVE-2017-15121",
    "CVE-2018-3665",
    "CVE-2018-3693",
    "CVE-2018-10882",
    "CVE-2018-10902",
    "CVE-2018-19985"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1514)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The function hso_get_config_data in
    drivers/net/usb/hso.c in the Linux kernel through
    4.19.8 reads if_num from the USB device (as a u8) and
    uses it to index a small array, resulting in an object
    out-of-bounds (OOB) read that potentially allows
    arbitrary read in the kernel address
    space.(CVE-2018-19985)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions (a commonly used performance
    optimization). There are three primary variants of the
    issue which differ in the way the speculative execution
    can be exploited. Variant CVE-2017-5754 relies on the
    fact that, on impacted microprocessors, during
    speculative execution of instruction permission faults,
    exception generation triggered by a faulting access is
    suppressed until the retirement of the whole
    instruction block. In a combination with the fact that
    memory accesses may populate the cache even when the
    block is being dropped and never committed (executed),
    an unprivileged local attacker could use this flaw to
    read privileged (kernel space) memory by conducting
    targeted cache side-channel attacks. Note:
    CVE-2017-5754 affects Intel x86-64 microprocessors. AMD
    x86-64 microprocessors are not affected by this
    issue.(CVE-2017-5754)

  - A non-privileged user is able to mount a fuse
    filesystem on RHEL 6 or 7 and crash a system if an
    application punches a hole in a file that does not end
    aligned to a page boundary.(CVE-2017-15121)

  - A flaw was found in the Linux kernel when attempting to
    'punch a hole' in files existing on an ext4 filesystem.
    When punching holes into a file races with the page
    fault of the same area, it is possible that freed
    blocks remain referenced from page cache pages mapped
    to process' address space.(CVE-2015-8839)

  - An industry-wide issue was found in the way many modern
    microprocessor designs have implemented speculative
    execution of instructions past bounds check. The flaw
    relies on the presence of a precisely-defined
    instruction sequence in the privileged code and the
    fact that memory writes occur to an address which
    depends on the untrusted value. Such writes cause an
    update into the microprocessor's data cache even for
    speculatively executed instructions that never actually
    commit (retire). As a result, an unprivileged attacker
    could use this flaw to influence speculative execution
    and/or read privileged memory by conducting targeted
    cache side-channel attacks.(CVE-2018-3693)

  - A Floating Point Unit (FPU) state information leakage
    flaw was found in the way the Linux kernel saved and
    restored the FPU state during task switch. Linux
    kernels that follow the 'Lazy FPU Restore' scheme are
    vulnerable to the FPU state information leakage issue.
    An unprivileged local attacker could use this flaw to
    read FPU state bits by conducting targeted cache
    side-channel attacks, similar to the Meltdown
    vulnerability disclosed earlier this
    year.(CVE-2018-3665)

  - A bug in the 32-bit compatibility layer of the ioctl
    handling code of the v4l2 video driver in the Linux
    kernel has been found. A memory protection mechanism
    ensuring that user-provided buffers always point to a
    userspace memory were disabled, allowing destination
    address to be in a kernel space. This flaw could be
    exploited by an attacker to overwrite a kernel memory
    from an unprivileged userspace process, leading to
    privilege escalation.(CVE-2017-13166)

  - It was found that the raw midi kernel driver does not
    protect against concurrent access which leads to a
    double realloc (double free) in
    snd_rawmidi_input_params() and
    snd_rawmidi_output_status() which are part of
    snd_rawmidi_ioctl() handler in rawmidi.c file. A
    malicious local attacker could possibly use this for
    privilege escalation.(CVE-2018-10902)

  - A flaw was found in the Linux kernel's implementation
    of valid_master_desc() in which a memory buffer would
    be compared to a userspace value with an incorrect size
    of comparison. By bruteforcing the comparison, an
    attacker could determine what was in memory after the
    description and possibly obtain sensitive information
    from kernel memory.(CVE-2017-13305)

  - A flaw was found in the Linux kernel's ext4 filesystem.
    A local user can cause an out-of-bound write in in
    fs/jbd2/transaction.c code, a denial of service, and a
    system crash by unmounting a crafted ext4 filesystem
    image.(CVE-2018-10882)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1514
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cc9be55");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3693");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-10902");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
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

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
