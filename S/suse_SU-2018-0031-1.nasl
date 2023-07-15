#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0031-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(105647);
  script_version("3.9");
  script_cvs_date("Date: 2019/09/10 13:51:46");

  script_cve_id("CVE-2017-11600", "CVE-2017-13167", "CVE-2017-15115", "CVE-2017-15868", "CVE-2017-16534", "CVE-2017-16538", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17558", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-8824");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2018:0031-1) (Meltdown) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 LTSS kernel was updated to receive
various security and bugfixes. This update adds mitigations for
various side channel attacks against modern CPUs that could disclose
content of otherwise unreadable memory (bnc#1068032).

  - CVE-2017-5753 / 'SpectreAttack': Local attackers on
    systems with modern CPUs featuring deep instruction
    pipelining could use attacker controllable speculative
    execution over code patterns in the Linux Kernel to leak
    content from otherwise not readable memory in the same
    address space, allowing retrieval of passwords,
    cryptographic keys and other secrets. This problem is
    mitigated by adding speculative fencing on affected code
    paths throughout the Linux kernel. This issue is
    addressed for the x86_64, IBM Power and IBM zSeries
    architecture.

  - CVE-2017-5715 / 'SpectreAttack': Local attackers on
    systems with modern CPUs featuring branch prediction
    could use mispredicted branches to speculatively execute
    code patterns that in turn could be made to leak other
    non-readable content in the same address space, an
    attack similar to CVE-2017-5753. This problem is
    mitigated by disabling predictive branches, depending on
    CPU architecture either by firmware updates and/or fixes
    in the user-kernel privilege boundaries. This is done
    with help of Linux Kernel fixes on the Intel/AMD x86_64
    and IBM zSeries architectures. On x86_64, this requires
    also updates of the CPU microcode packages, delivered in
    separate updates. For IBM Power and zSeries the required
    firmware updates are supplied over regular channels by
    IBM. As this feature can have a performance impact, it
    can be disabled using the 'nospec' kernel commandline
    option.

  - CVE-2017-5754 / 'MeltdownAttack': Local attackers on
    systems with modern CPUs featuring deep instruction
    pipelining could use code patterns in userspace to
    speculative executive code that would read otherwise
    read protected memory, an attack similar to
    CVE-2017-5753. This problem is mitigated by unmapping
    the Linux Kernel from the user address space during user
    code execution, following a approach called 'KAISER'.
    The terms used here are 'KAISER' / 'Kernel Address
    Isolation' and 'PTI' / 'Page Table Isolation'. This
    update does this on the x86_64 architecture, it is not
    required on the IBM zSeries architecture. This feature
    can be enabled / disabled by the 'pti=[on|off|auto]' or
    'nopti' commandline options. The following security bugs
    were fixed :

  - CVE-2017-15868: The bnep_add_connection function in
    net/bluetooth/bnep/core.c in the Linux kernel did not
    ensure that an l2cap socket is available, which allowed
    local users to gain privileges via a crafted application
    (bnc#1071470).

  - CVE-2017-13167: An elevation of privilege vulnerability
    in the kernel sound timer. (bnc#1072876).

  - CVE-2017-16538: drivers/media/usb/dvb-usb-v2/lmedm04.c
    in the Linux kernel allowed local users to cause a
    denial of service (general protection fault and system
    crash) or possibly have unspecified other impact via a
    crafted USB device, related to a missing warm-start
    check and incorrect attach timing
    (dm04_lme2510_frontend_attach versus dm04_lme2510_tuner)
    (bnc#1066569).

  - CVE-2017-17558: The usb_destroy_configuration function
    in drivers/usb/core/config.c in the USB core subsystem
    in the Linux kernel did not consider the maximum number
    of configurations and interfaces before attempting to
    release resources, which allowed local users to cause a
    denial of service (out-of-bounds write access) or
    possibly have unspecified other impact via a crafted USB
    device (bnc#1072561).

  - CVE-2017-17450: net/netfilter/xt_osf.c in the Linux
    kernel did not require the CAP_NET_ADMIN capability for
    add_callback and remove_callback operations, which
    allowed local users to bypass intended access
    restrictions because the xt_osf_fingers data structure
    is shared across all net namespaces (bnc#1071695).

  - CVE-2017-17449: The __netlink_deliver_tap_skb function
    in net/netlink/af_netlink.c in the Linux kernel through
    4.14.4, when CONFIG_NLMON is enabled, did not restrict
    observations of Netlink messages to a single net
    namespace, which allowed local users to obtain sensitive
    information by leveraging the CAP_NET_ADMIN capability
    to sniff an nlmon interface for all Netlink activity on
    the system (bnc#1071694).

  - CVE-2017-17448: net/netfilter/nfnetlink_cthelper.c in
    the Linux kernel did not require the CAP_NET_ADMIN
    capability for new, get, and del operations, which
    allowed local users to bypass intended access
    restrictions because the nfnl_cthelper_list data
    structure is shared across all net namespaces
    (bnc#1071693).

  - CVE-2017-8824: The dccp_disconnect function in
    net/dccp/proto.c in the Linux kernel allowed local users
    to gain privileges or cause a denial of service
    (use-after-free) via an AF_UNSPEC connect system call
    during the DCCP_LISTEN state (bnc#1070771).

  - CVE-2017-15115: The sctp_do_peeloff function in
    net/sctp/socket.c in the Linux kernel did not check
    whether the intended netns is used in a peel-off action,
    which allowed local users to cause a denial of service
    (use-after-free and system crash) or possibly have
    unspecified other impact via crafted system calls
    (bnc#1068671).

  - CVE-2017-11600: net/xfrm/xfrm_policy.c in the Linux
    kernel through 4.12.3, when CONFIG_XFRM_MIGRATE is
    enabled, did not ensure that the dir value of
    xfrm_userpolicy_id is XFRM_POLICY_MAX or less, which
    allowed local users to cause a denial of service
    (out-of-bounds access) or possibly have unspecified
    other impact via an XFRM_MSG_MIGRATE xfrm Netlink
    message (bnc#1050231).

  - CVE-2017-16534: The cdc_parse_cdc_header function in
    drivers/usb/core/message.c in the Linux kernel allowed
    local users to cause a denial of service (out-of-bounds
    read and system crash) or possibly have unspecified
    other impact via a crafted USB device (bnc#1066693).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1066693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1067678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1072876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11600/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13167/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15115/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15868/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16534/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16538/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17448/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17449/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17450/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17558/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5753/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5754/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8824/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180031-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31b5dbbf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2018-24=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-24=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-24=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2018-24=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_69-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_74-60_64_69-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_69-default-1-2.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kgraft-patch-3_12_74-60_64_69-xen-1-2.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.74-60.64.69.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.74-60.64.69.1")) flag++;


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
