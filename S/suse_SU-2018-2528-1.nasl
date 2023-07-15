#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2528-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112147);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-10981", "CVE-2018-10982", "CVE-2018-11806", "CVE-2018-12617", "CVE-2018-12891", "CVE-2018-12893", "CVE-2018-3639", "CVE-2018-3646", "CVE-2018-3665");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2018:2528-1) (Foreshadow) (Meltdown) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues: These security issue
were fixed :

  - CVE-2018-3646: Systems with microprocessors utilizing
    speculative execution and address translations may have
    allowed unauthorized disclosure of information residing
    in the L1 data cache to an attacker with local user
    access with guest OS privilege via a terminal page fault
    and a side-channel analysis (bsc#1091107, bsc#1027519).

  - CVE-2018-12617: An integer overflow that could cause a
    segmentation fault in qmp_guest_file_read() with
    g_malloc() in qemu-guest-agent was fixed (bsc#1098744)

  - CVE-2018-3665: System software utilizing Lazy FP state
    restore technique on systems using Intel Core-based
    microprocessors may potentially allow a local process to
    infer data from another process through a speculative
    execution side channel. (bsc#1095242)

  - CVE-2018-3639: Systems with microprocessors utilizing
    speculative execution and speculative execution of
    memory reads before the addresses of all prior memory
    writes are known may allow unauthorized disclosure of
    information to an attacker with local user access via a
    side-channel analysis, aka Speculative Store Bypass
    (SSB), Variant 4. (bsc#1092631)

  - CVE-2017-5715: Systems with microprocessors utilizing
    speculative execution and indirect branch prediction may
    allow unauthorized disclosure of information to an
    attacker with local user access via a side-channel
    analysis. (bsc#1074562)

  - CVE-2017-5753: Systems with microprocessors utilizing
    speculative execution and branch prediction may allow
    unauthorized disclosure of information to an attacker
    with local user access via a side-channel analysis.
    (bsc#1074562)

  - CVE-2017-5754: Systems with microprocessors utilizing
    speculative execution and indirect branch prediction may
    allow unauthorized disclosure of information to an
    attacker with local user access via a side-channel
    analysis of the data cache. (bsc#1074562)

  - CVE-2018-12891: Certain PV MMU operations may take a
    long time to process. For that reason Xen explicitly
    checks for the need to preempt the current vCPU at
    certain points. A few rarely taken code paths did bypass
    such checks. By suitably enforcing the conditions
    through its own page table contents, a malicious guest
    may cause such bypasses to be used for an unbounded
    number of iterations. A malicious or buggy PV guest may
    cause a Denial of Service (DoS) affecting the entire
    host. Specifically, it may prevent use of a physical CPU
    for an indeterminate period of time. (bsc#1097521)

  - CVE-2018-12893: One of the fixes in XSA-260 added some
    safety checks to help prevent Xen livelocking with debug
    exceptions. Unfortunately, due to an oversight, at least
    one of these safety checks can be triggered by a guest.
    A malicious PV guest can crash Xen, leading to a Denial
    of Service. Only x86 PV guests can exploit the
    vulnerability. x86 HVM and PVH guests cannot exploit the
    vulnerability. An attacker needs to be able to control
    hardware debugging facilities to exploit the
    vulnerability, but such permissions are typically
    available to unprivileged users. (bsc#1097522)

  - CVE-2018-11806: m_cat in slirp/mbuf.c in Qemu has a
    heap-based buffer overflow via incoming fragmented
    datagrams. (bsc#1096224)

  - CVE-2018-10982: An issue was discovered in Xen allowed
    x86 HVM guest OS users to cause a denial of service
    (unexpectedly high interrupt number, array overrun, and
    hypervisor crash) or possibly gain hypervisor privileges
    by setting up an HPET timer to deliver interrupts in
    IO-APIC mode, aka vHPET interrupt injection.
    (bsc#1090822)

  - CVE-2018-10981: An issue was discovered in Xen that
    allowed x86 HVM guest OS users to cause a denial of
    service (host OS infinite loop) in situations where a
    QEMU device model attempts to make invalid transitions
    between states of a request. (bsc#1090823) Following
    bugs were fixed :

  - After updating to kernel 3.0.101-0.47.106.32-xen system
    crashes in check_bugs() (bsc#1097206)

  - bsc#1079730 - in xen-kmp, unplug emulated devices after
    migration This is required since xen-4.10 and/or
    qemu-2.10 because the state of unplug is not propagated
    from one dom0 to another. Without this unplug qemu's
    block-backend will be unable to open qcow2 disks on the
    receiving dom0

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1090823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1097522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098744"
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
    value:"https://www.suse.com/security/cve/CVE-2018-10981/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10982/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-11806/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12617/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12891/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12893/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3639/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3646/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-3665/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182528-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07f34b23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-xen-13752=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-xen-13752=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-xen-13752=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_21_3.0.101_0.47.106.43-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_21_3.0.101_0.47.106.43-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_21_3.0.101_0.47.106.43-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.5_21-45.25.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_21_3.0.101_0.47.106.43-45.25.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
