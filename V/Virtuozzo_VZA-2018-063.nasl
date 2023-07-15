#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112206);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id(
    "CVE-2017-13215",
    "CVE-2018-10675",
    "CVE-2018-3620",
    "CVE-2018-3646",
    "CVE-2018-3693",
    "CVE-2018-5390",
    "CVE-2018-7566"
  );

  script_name(english:"Virtuozzo 7 : OVMF / crit / criu / criu-devel / ksm-vz / etc (VZA-2018-063)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Virtuozzo host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the OVMF / crit / criu / criu-devel /
ksm-vz / etc packages installed, the Virtuozzo installation on the
remote host is affected by the following vulnerabilities :

  - A flaw was found in the Linux kernel's skcipher
    component, which affects the skcipher_recvmsg function.
    Attackers using a specific input can lead to a
    privilege escalation.

  - Modern operating systems implement virtualization of
    physical memory to efficiently use available system
    resources and provide inter-domain protection through
    access control and isolation. The L1TF issue was found
    in the way the x86 microprocessor designs have
    implemented speculative execution of instructions (a
    commonly used performance optimisation) in combination
    with handling of page-faults caused by terminated
    virtual to physical address resolving process. As a
    result, an unprivileged attacker could use this flaw to
    read privileged memory of the kernel or other processes
    and/or cross guest/host boundaries to read host memory
    by conducting targeted cache side-channel attacks.

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
    cache side-channel attacks.

  - A flaw named SegmentSmack was found in the way the
    Linux kernel handled specially crafted TCP packets. A
    remote attacker could use this flaw to trigger time and
    calculation expensive calls to tcp_collapse_ofo_queue()
    and tcp_prune_ofo_queue() functions by sending
    specially modified packets within ongoing TCP sessions
    which could lead to a CPU saturation and hence a denial
    of service on the system. Maintaining the denial of
    service condition requires continuous two-way TCP
    sessions to a reachable open port, thus the attacks
    cannot be performed using spoofed IP addresses.

  - ALSA sequencer core initializes the event pool on
    demand by invoking snd_seq_pool_init() when the first
    write happens and the pool is empty. A user can reset
    the pool size manually via ioctl concurrently, and this
    may lead to UAF or out-of-bound access.

  - The do_get_mempolicy() function in mm/mempolicy.c in
    the Linux kernel allows local users to hit a
    use-after-free bug via crafted system calls and thus
    cause a denial of service (DoS) or possibly have
    unspecified other impact. Due to the nature of the
    flaw, privilege escalation cannot be fully ruled out.

Note that Tenable Network Security has extracted the preceding
description block directly from the Virtuozzo security advisory.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://help.virtuozzo.com/customer/portal/articles/2953355");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/3553061");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2384");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/L1TF");
  script_set_attribute(attribute:"solution", value:
"Update the affected OVMF / crit / criu / criu-devel / ksm-vz / etc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:OVMF");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:criu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:ksm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libcompel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libcompel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:libprlsdk-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-legacy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:prl-disp-service-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:python-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-img-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-common-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-tools-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:qemu-kvm-vz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:virtuozzo:virtuozzo:vzkernel-headers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:virtuozzo:virtuozzo:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Virtuozzo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Virtuozzo/release", "Host/Virtuozzo/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Virtuozzo/release");
if (isnull(release) || "Virtuozzo" >!< release) audit(AUDIT_OS_NOT, "Virtuozzo");
os_ver = pregmatch(pattern: "Virtuozzo Linux release ([0-9]+\.[0-9])(\D|$)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Virtuozzo");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Virtuozzo 7.x", "Virtuozzo " + os_ver);

if (!get_kb_item("Host/Virtuozzo/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Virtuozzo", cpu);

flag = 0;

pkgs = ["OVMF-20171011-4.git92d07e48907f.vz7.4.1",
        "crit-3.8.0.37-1.vz7",
        "criu-3.8.0.37-1.vz7",
        "criu-devel-3.8.0.37-1.vz7",
        "ksm-vz-2.10.0-21.4.vz7.37.1",
        "libcompel-3.8.0.37-1.vz7",
        "libcompel-devel-3.8.0.37-1.vz7",
        "libprlcommon-7.0.145.3-1.vz7",
        "libprlcommon-devel-7.0.145.3-1.vz7",
        "libprlsdk-7.0.217-5.vz7",
        "libprlsdk-devel-7.0.217-5.vz7",
        "libprlsdk-headers-7.0.217-5.vz7",
        "libprlsdk-python-7.0.217-5.vz7",
        "prl-disp-legacy-7.0.843.38-5.vz7",
        "prl-disp-service-7.0.843.38-5.vz7",
        "prl-disp-service-tests-7.0.843.38-5.vz7",
        "python-criu-3.8.0.37-1.vz7",
        "qemu-img-vz-2.10.0-21.4.vz7.37.1",
        "qemu-kvm-common-vz-2.10.0-21.4.vz7.37.1",
        "qemu-kvm-tools-vz-2.10.0-21.4.vz7.37.1",
        "qemu-kvm-vz-2.10.0-21.4.vz7.37.1",
        "vzkernel-3.10.0-862.11.6.vz7.64.7",
        "vzkernel-debug-3.10.0-862.11.6.vz7.64.7",
        "vzkernel-debug-devel-3.10.0-862.11.6.vz7.64.7",
        "vzkernel-devel-3.10.0-862.11.6.vz7.64.7",
        "vzkernel-headers-3.10.0-862.11.6.vz7.64.7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"Virtuozzo-7", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OVMF / crit / criu / criu-devel / ksm-vz / etc");
}
