#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117569);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-18255",
    "CVE-2018-10021",
    "CVE-2018-1066",
    "CVE-2018-1068",
    "CVE-2018-5803",
    "CVE-2018-7566",
    "CVE-2018-7757",
    "CVE-2018-7995"
  );

  script_name(english:"EulerOS Virtualization 2.5.0 : kernel (EulerOS-SA-2018-1260)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw was found in the Linux kernel's client-side
    implementation of the cifs protocol. This flaw allows
    an attacker controlling the server to kernel panic a
    client which has the CIFS server
    mounted.(CVE-2018-1066)

  - In the Linux Kernel before version 4.15.8, 4.14.25,
    4.9.87, 4.4.121, 4.1.51, and 3.2.102, an error in the
    '_sctp_make_chunk()' function
    (net/sctp/sm_make_chunk.c) when handling SCTP packets
    length can be exploited to cause a kernel
    crash.(CVE-2018-5803)

  - Memory leak in the sas_smp_get_phy_events function in
    drivers/scsi/libsas/sas_expander.c in the Linux kernel
    allows local users to cause a denial of service (kernel
    memory exhaustion) via multiple read accesses to files
    in the /sys/class/sas_phy directory.(CVE-2018-7757)

  - A race condition in the store_int_with_restart()
    function in arch/x86/kernel/cpu/mcheck/mce.c in the
    Linux kernel allows local users to cause a denial of
    service (panic) by leveraging root access to write to
    the check_interval file in a
    /sys/devices/system/machinecheck/machinecheck (cpu
    number) directory.(CVE-2018-7995)

  - ALSA sequencer core initializes the event pool on
    demand by invoking snd_seq_pool_init() when the first
    write happens and the pool is empty. A user can reset
    the pool size manually via ioctl concurrently, and this
    may lead to UAF or out-of-bound access.(CVE-2018-7566)

  - A flaw was found in the Linux kernel's implementation
    of 32-bit syscall interface for bridging. This allowed
    a privileged user to arbitrarily write to a limited
    range of kernel memory.(CVE-2018-1068)

  - A vulnerability was found in the Linux kernel's
    kernel/events/core.c:perf_cpu_time_max_percent_handler(
    ) function. Local privileged users could exploit this
    flaw to cause a denial of service due to integer
    overflow or possibly have unspecified other
    impact.(CVE-2017-18255)

  - The code in the drivers/scsi/libsas/sas_scsi_host.c
    file in the Linux kernel allow a physically proximate
    attacker to cause a memory leak in the ATA command
    queue and, thus, denial of service by triggering
    certain failure conditions.(CVE-2018-10021)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1260
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d22ac81");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.5.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.61.59.66_43",
        "kernel-devel-3.10.0-327.61.59.66_43",
        "kernel-headers-3.10.0-327.61.59.66_43",
        "kernel-tools-3.10.0-327.61.59.66_43",
        "kernel-tools-libs-3.10.0-327.61.59.66_43",
        "kernel-tools-libs-devel-3.10.0-327.61.59.66_43"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
