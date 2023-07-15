#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2507-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94038);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-6258", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094", "CVE-2016-7154");
  script_xref(name:"IAVB", value:"2016-B-0118-S");
  script_xref(name:"IAVB", value:"2016-B-0140-S");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2016:2507-1) (Bunker Buster)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues. These security issues were
fixed :

  - CVE-2016-7092: The get_page_from_l3e function in
    arch/x86/mm.c in Xen allowed local 32-bit PV guest OS
    administrators to gain host OS privileges via vectors
    related to L3 recursive pagetables (bsc#995785)

  - CVE-2016-7093: Xen allowed local HVM guest OS
    administrators to overwrite hypervisor memory and
    consequently gain host OS privileges by leveraging
    mishandling of instruction pointer truncation during
    emulation (bsc#995789)

  - CVE-2016-7094: Buffer overflow in Xen allowed local x86
    HVM guest OS administrators on guests running with
    shadow paging to cause a denial of service via a
    pagetable update (bsc#995792)

  - CVE-2016-7154: Use-after-free vulnerability in the FIFO
    event channel code in Xen allowed local guest OS
    administrators to cause a denial of service (host crash)
    and possibly execute arbitrary code or obtain sensitive
    information via an invalid guest frame number
    (bsc#997731)

  - CVE-2016-6836: VMWARE VMXNET3 NIC device allowed
    privileged user inside the guest to leak information. It
    occured while processing transmit(tx) queue, when it
    reaches the end of packet (bsc#994761)

  - CVE-2016-6888: A integer overflow int the VMWARE VMXNET3
    NIC device support, during the initialisation of new
    packets in the device, could have allowed a privileged
    user inside guest to crash the Qemu instance resulting
    in DoS (bsc#994772)

  - CVE-2016-6833: A use-after-free issue in the VMWARE
    VMXNET3 NIC device support allowed privileged user
    inside guest to crash the Qemu instance resulting in DoS
    (bsc#994775)

  - CVE-2016-6835: Buffer overflow in the VMWARE VMXNET3 NIC
    device support, causing an OOB read access (bsc#994625)

  - CVE-2016-6834: A infinite loop during packet
    fragmentation in the VMWARE VMXNET3 NIC device support
    allowed privileged user inside guest to crash the Qemu
    instance resulting in DoS (bsc#994421)

  - CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in
    Xen allowed local 32-bit PV guest OS administrators to
    gain host OS privileges by leveraging fast-paths for
    updating pagetable entries (bsc#988675)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=966467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=970135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=971949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=988675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=990970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=991934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=992224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=993507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994136"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=995785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=995789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=995792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=997731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6258/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6833/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6834/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6835/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6836/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6888/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7092/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7093/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7094/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7154/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162507-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?181aa488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-xen-12782=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-xen-12782=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-xen-12782=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_08_3.0.101_80-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-libs-4.4.4_08-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_08-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-4.4.4_08-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-doc-html-4.4.4_08-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_08-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-tools-4.4.4_08-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"xen-kmp-pae-4.4.4_08_3.0.101_80-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-kmp-default-4.4.4_08_3.0.101_80-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-libs-4.4.4_08-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-tools-domU-4.4.4_08-40.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"xen-kmp-pae-4.4.4_08_3.0.101_80-40.2")) flag++;


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
