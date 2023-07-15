#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0555-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107055);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-1142857", "CVE-2017-13215", "CVE-2017-17741", "CVE-2017-18017", "CVE-2017-18079", "CVE-2017-5715", "CVE-2017-5754", "CVE-2018-1000004", "CVE-2018-5332", "CVE-2018-5333");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2018:0555-1) (Meltdown) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various
security and bugfixes. The following security bugs were fixed :

  - CVE-2017-5715: Systems with microprocessors utilizing
    speculative execution and indirect branch prediction may
    allow unauthorized disclosure of information to an
    attacker with local user access via a side-channel
    analysis (bnc#1068032). The previous fix using CPU
    Microcode has been complemented by building the Linux
    Kernel with return trampolines aka 'retpolines'.

  - CVE-2018-5332: In the Linux kernel the
    rds_message_alloc_sgs() function did not validate a
    value that is used during DMA page allocation, leading
    to a heap-based out-of-bounds write (related to the
    rds_rdma_extra_size function in net/rds/rdma.c)
    (bnc#1075621).

  - CVE-2018-5333: In the Linux kernel the rds_cmsg_atomic
    function in net/rds/rdma.c mishandled cases where page
    pinning fails or an invalid address is supplied, leading
    to an rds_atomic_free_op NULL pointer dereference
    (bnc#1075617).

  - CVE-2017-18017: The tcpmss_mangle_packet function in
    net/netfilter/xt_TCPMSS.c in the Linux kernel allowed
    remote attackers to cause a denial of service
    (use-after-free and memory corruption) or possibly have
    unspecified other impact by leveraging the presence of
    xt_TCPMSS in an iptables action (bnc#1074488).

  - CVE-2017-18079: drivers/input/serio/i8042.c in the Linux
    kernel allowed attackers to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact because the port->exists
    value can change after it is validated (bnc#1077922).

  - CVE-2015-1142857: On multiple SR-IOV cars it is possible
    for VF's assigned to guests to send ethernet flow
    control pause frames via the PF. (bnc#1077355).

  - CVE-2017-17741: The KVM implementation in the Linux
    kernel allowed attackers to obtain potentially sensitive
    information from kernel memory, aka a write_mmio
    stack-based out-of-bounds read, related to
    arch/x86/kvm/x86.c and include/trace/events/kvm.h
    (bnc#1073311).

  - CVE-2017-13215: A elevation of privilege vulnerability
    in the Upstream kernel skcipher. (bnc#1075908).

  - CVE-2018-1000004: In the Linux kernel a race condition
    vulnerability existed in the sound system, this can lead
    to a deadlock and denial of service condition
    (bnc#1076017).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1059174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1060682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1064861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1069508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1073311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1075994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1077922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1078875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1080774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=936530"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=962257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1142857/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13215/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17741/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18017/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18079/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1000004/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5332/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5333/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180555-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be83bfc0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-kernel-20180207-13491=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-kernel-20180207-13491=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-20180207-13491=1

SUSE Linux Enterprise Real Time Extension 11-SP4:zypper in -t patch
slertesp4-kernel-20180207-13491=1

SUSE Linux Enterprise High Availability Extension 11-SP4:zypper in -t
patch slehasp4-kernel-20180207-13491=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-kernel-20180207-13491=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"kernel-default-man-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-base-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-default-devel-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-source-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-syms-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-base-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"kernel-trace-devel-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-base-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-base-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-xen-devel-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-base-3.0.101-108.35.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"kernel-pae-devel-3.0.101-108.35.1")) flag++;


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
