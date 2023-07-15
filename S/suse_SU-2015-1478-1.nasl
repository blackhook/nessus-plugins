#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1478-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85764);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-8086", "CVE-2014-8159", "CVE-2014-9683", "CVE-2015-0777", "CVE-2015-1420", "CVE-2015-1421", "CVE-2015-1805", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3636", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5707");
  script_bugtraq_id(70376, 72356, 72357, 72643, 72729, 72730, 73014, 73060, 73699, 73921, 74235, 74315, 74450, 74951, 75356, 75510);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2015:1478-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise Server 11 SP2 LTSS kernel was updated to
receive various security and bugfixes.

The following security bugs were fixed :

  - CVE-2015-5707: An integer overflow in the SCSI generic
    driver could be potentially used by local attackers to
    crash the kernel or execute code.

  - CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux
    kernel did not prevent the TS_COMPAT flag from reaching
    a user-mode task, which might have allowed local users
    to bypass the seccomp or audit protection mechanism via
    a crafted application that uses the (1) fork or (2)
    close system call, as demonstrated by an attack against
    seccomp before 3.16 (bnc#926240).

  - CVE-2015-0777: drivers/xen/usbback/usbback.c in the
    Linux kernel allowed guest OS users to obtain sensitive
    information from uninitialized locations in host OS
    kernel memory via unspecified vectors (bnc#917830).

  - CVE-2015-2150: Xen and the Linux kernel did not properly
    restrict access to PCI command registers, which might
    have allowed local guest users to cause a denial of
    service (non-maskable interrupt and host crash) by
    disabling the (1) memory or (2) I/O decoding for a PCI
    Express device and then accessing the device, which
    triggers an Unsupported Request (UR) response
    (bnc#919463).

  - CVE-2015-5364: A remote denial of service (hang) via UDP
    flood with incorrect package checksums was fixed.
    (bsc#936831).

  - CVE-2015-5366: A remote denial of service (unexpected
    error returns) via UDP flood with incorrect package
    checksums was fixed. (bsc#936831).

  - CVE-2015-1420: CVE-2015-1420: Race condition in the
    handle_to_path function in fs/fhandle.c in the Linux
    kernel allowed local users to bypass intended size
    restrictions and trigger read operations on additional
    memory locations by changing the handle_bytes value of a
    file handle during the execution of this function
    (bnc#915517).

  - CVE-2015-4700: A local user could have created a bad
    instruction in the JIT processed BPF code, leading to a
    kernel crash (bnc#935705).

  - CVE-2015-1805: The (1) pipe_read and (2) pipe_write
    implementations in fs/pipe.c in the Linux kernel did not
    properly consider the side effects of failed
    __copy_to_user_inatomic and __copy_from_user_inatomic
    calls, which allowed local users to cause a denial of
    service (system crash) or possibly gain privileges via a
    crafted application, aka an 'I/O vector array overrun'
    (bnc#933429).

  - CVE-2015-3331: The __driver_rfc4106_decrypt function in
    arch/x86/crypto/aesni-intel_glue.c in the Linux kernel
    did not properly determine the memory locations used for
    encrypted data, which allowed context-dependent
    attackers to cause a denial of service (buffer overflow
    and system crash) or possibly execute arbitrary code by
    triggering a crypto API call, as demonstrated by use of
    a libkcapi test program with an AF_ALG(aead) socket
    (bnc#927257).

  - CVE-2015-2922: The ndisc_router_discovery function in
    net/ipv6/ndisc.c in the Neighbor Discovery (ND) protocol
    implementation in the IPv6 stack in the Linux kernel
    allowed remote attackers to reconfigure a hop-limit
    setting via a small hop_limit value in a Router
    Advertisement (RA) message (bnc#922583).

  - CVE-2015-2041: net/llc/sysctl_net_llc.c in the Linux
    kernel used an incorrect data type in a sysctl table,
    which allowed local users to obtain potentially
    sensitive information from kernel memory or possibly
    have unspecified other impact by accessing a sysctl
    entry (bnc#919007).

  - CVE-2015-3636: The ping_unhash function in
    net/ipv4/ping.c in the Linux kernel did not initialize a
    certain list data structure during an unhash operation,
    which allowed local users to gain privileges or cause a
    denial of service (use-after-free and system crash) by
    leveraging the ability to make a SOCK_DGRAM socket
    system call for the IPPROTO_ICMP or IPPROTO_ICMPV6
    protocol, and then making a connect system call after a
    disconnect (bnc#929525).

  - CVE-2014-8086: Race condition in the
    ext4_file_write_iter function in fs/ext4/file.c in the
    Linux kernel allowed local users to cause a denial of
    service (file unavailability) via a combination of a
    write action and an F_SETFL fcntl operation for the
    O_DIRECT flag (bnc#900881).

  - CVE-2014-8159: The InfiniBand (IB) implementation in the
    Linux kernel did not properly restrict use of User Verbs
    for registration of memory regions, which allowed local
    users to access arbitrary physical memory locations, and
    consequently cause a denial of service (system crash) or
    gain privileges, by leveraging permissions on a uverbs
    device under /dev/infiniband/ (bnc#914742).

  - CVE-2014-9683: Off-by-one error in the
    ecryptfs_decode_from_filename function in
    fs/ecryptfs/crypto.c in the eCryptfs subsystem in the
    Linux kernel allowed local users to cause a denial of
    service (buffer overflow and system crash) or possibly
    gain privileges via a crafted filename (bnc#918333).

  - CVE-2015-2042: net/rds/sysctl.c in the Linux kernel used
    an incorrect data type in a sysctl table, which allowed
    local users to obtain potentially sensitive information
    from kernel memory or possibly have unspecified other
    impact by accessing a sysctl entry (bnc#919018).

  - CVE-2015-1421: Use-after-free vulnerability in the
    sctp_assoc_update function in net/sctp/associola.c in
    the Linux kernel allowed remote attackers to cause a
    denial of service (slab corruption and panic) or
    possibly have unspecified other impact by triggering an
    INIT collision that leads to improper handling of
    shared-key data (bnc#915577).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=798406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=821931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=860593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=879878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=891087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=897995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=898693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=900881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=904671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=908870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=909477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=912916"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=914742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=915577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=916010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=918333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=921769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=922583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=923245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=927257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=928801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=929525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=930934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=931474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=933429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=935705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=937986"
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
    value:"https://www.suse.com/security/cve/CVE-2014-8086/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8159/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9683/"
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
    value:"https://www.suse.com/security/cve/CVE-2015-1421/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1805/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2041/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2042/"
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
    value:"https://www.suse.com/security/cve/CVE-2015-2922/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3331/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3636/"
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
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151478-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a926165a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-kernel-20150819-12065=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-kernel-20150819-12065=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-base-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-devel-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-source-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-syms-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-base-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-devel-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.37.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.37.1")) flag++;


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
