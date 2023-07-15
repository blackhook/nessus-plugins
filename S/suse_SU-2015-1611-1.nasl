#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1611-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86121);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-0777", "CVE-2015-1420", "CVE-2015-1805", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-4167", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5707");
  script_bugtraq_id(72357, 73014, 73699, 73921, 74951, 74963, 74964, 75001, 75356, 75510);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2015:1611-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP3 kernel was updated to receive various
security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-5707: An integer overflow in the SCSI generic
    driver could be potentially used by local attackers to
    crash the kernel or execute code (bsc#940338).

  - CVE-2015-5364: A remote denial of service (hang) via UDP
    flood with incorrect package checksums was fixed.
    (bsc#936831).

  - CVE-2015-5366: A remote denial of service (unexpected
    error returns) via UDP flood with incorrect package
    checksums was fixed. (bsc#936831).

  - CVE-2015-1420: A race condition in the handle_to_path
    function in fs/fhandle.c in the Linux kernel allowed
    local users to bypass intended size restrictions and
    trigger read operations on additional memory locations
    by changing the handle_bytes value of a file handle
    during the execution of this function (bnc#915517).

  - CVE-2015-4700: A local user could have created a bad
    instruction in the JIT processed BPF code, leading to a
    kernel crash (bnc#935705).

  - CVE-2015-4167: The UDF filesystem in the Linux kernel
    was vulnerable to a crash which could occur while
    fetching inode information from a corrupted/malicious
    udf file system image. (bsc#933907).

  - CVE-2014-9728 CVE-2014-9729 CVE-2014-9730 CVE-2014-9731:
    Various issues in handling UDF filesystems in the Linux
    kernel allowed the corruption of kernel memory and other
    issues. An attacker able to mount a corrupted/malicious
    UDF file system image could cause the kernel to crash.
    (bsc#933904 bsc#933896)

  - CVE-2015-2150: The Linux kernel did not properly
    restrict access to PCI command registers, which might
    have allowed local guest users to cause a denial of
    service (non-maskable interrupt and host crash) by
    disabling the (1) memory or (2) I/O decoding for a PCI
    Express device and then accessing the device, which
    triggers an Unsupported Request (UR) response
    (bsc#919463).

  - CVE-2015-0777: drivers/xen/usbback/usbback.c as used in
    the Linux kernel 2.6.x and 3.x in SUSE Linux
    distributions, allowed guest OS users to obtain
    sensitive information from uninitialized locations in
    host OS kernel memory via unspecified vectors
    (bnc#917830).

  - CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux
    kernel did not prevent the TS_COMPAT flag from reaching
    a user-mode task, which might have allowed local users
    to bypass the seccomp or audit protection mechanism via
    a crafted application that uses the (1) fork or (2)
    close system call, as demonstrated by an attack against
    seccomp before 3.16 (bnc#926240).

  - CVE-2015-1805: The Linux kernels implementation of
    vectored pipe read and write functionality did not take
    into account the I/O vectors that were already processed
    when retrying after a failed atomic access operation,
    potentially resulting in memory corruption due to an I/O
    vector array overrun. A local, unprivileged user could
    use this flaw to crash the system or, potentially,
    escalate their privileges on the system. (bsc#933429).

Also 

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=851068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=867362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=873385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=883380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=886785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=894936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=920110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=920250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=920733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=921430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=923245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=924701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=925903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=927355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=927786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=931538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=932348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=932458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=933429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=933896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=933904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=933907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=933936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=934742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=934944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=935053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=935572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=935705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=935866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=935906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=939910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=939994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=940398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=942350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9728/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9729/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9730/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9731/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0777/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1420/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1805/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2150/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2830/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4167/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4700/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5364/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5366/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5707/"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151611-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?441d7fc3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-kernel-201508-12100=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-kernel-201508-12100=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-201508-12100=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-kernel-201508-12100=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-kernel-201508-12100=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-source-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-syms-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-source-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-syms-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.67.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
