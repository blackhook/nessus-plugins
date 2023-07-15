#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0762-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(108533);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2017-15119", "CVE-2017-15124", "CVE-2017-16845", "CVE-2017-17381", "CVE-2017-18043", "CVE-2017-5715", "CVE-2018-5683", "CVE-2018-7550");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2018:0762-1) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu fixes the following issues: This update has the
next round of Spectre v2 related patches, which now integrate with
corresponding changes in libvirt. (CVE-2017-5715 bsc#1068032) The
January 2018 release of qemu initially addressed the Spectre v2
vulnerability for KVM guests by exposing the spec-ctrl feature for all
x86 vcpu types, which was the quick and dirty approach, but not the
proper solution. We replaced our initial patch by the patches from
upstream. This update defines spec_ctrl and ibpb cpu feature flags as
well as new cpu models which are clones of existing models with either
-IBRS or -IBPB added to the end of the model name. These new vcpu
models explicitly include the new feature(s), whereas the feature
flags can be added to the cpu parameter as with other features. In
short, for continued Spectre v2 protection, ensure that either the
appropriate cpu feature flag is added to the QEMU command-line, or one
of the new cpu models is used. Although migration from older versions
is supported, the new cpu features won't be properly exposed to the
guest until it is restarted with the cpu features explicitly added. A
reboot is insufficient. A warning patch is added which attempts to
detect a migration from a qemu version which had the quick and dirty
fix (it only detects certain cases, but hopefully is helpful.) For
additional information on Spectre v2 as it relates to QEMU, see:
https://www.qemu.org/2018/02/14/qemu-2-11-1-and-spectre-update/ A
patch is added to continue to detect Spectre v2 mitigation features
(as shown by cpuid), and if found provide that feature to guests, even
if running on older KVM (kernel) versions which do not yet expose that
feature to QEMU. (bsc#1082276) These two patches will be removed when
we can reasonably assume everyone is running with the appropriate
updates. Spectre fixes for IBM Z Series were included by providing
more hw features to guests (bsc#1076813) Also security fixes for the
following CVE issues are included :

  - CVE-2017-17381: The Virtio Vring implementation in QEMU
    allowed local OS guest users to cause a denial of
    service (divide-by-zero error and QEMU process crash) by
    unsetting vring alignment while updating Virtio rings.
    (bsc#1071228)

  - CVE-2017-16845: The PS2 driver in Qemu did not validate
    'rptr' and 'count' values during guest migration,
    leading to out-of-bounds access. (bsc#1068613)

  - CVE-2017-15119: The Network Block Device (NBD) server in
    Quick Emulator (QEMU), was vulnerable to a denial of
    service issue. It could occur if a client sent large
    option requests, making the server waste CPU time on
    reading up to 4GB per request. A client could use this
    flaw to keep the NBD server from serving other requests,
    resulting in DoS. (bsc#1070144)

  - CVE-2017-18043: Integer overflow in the macro ROUND_UP
    (n, d) in Quick Emulator (Qemu) allowed a user to cause
    a denial of service (Qemu process crash). (bsc#1076775)

  - CVE-2018-5683: The VGA driver in Qemu allowed local OS
    guest privileged users to cause a denial of service
    (out-of-bounds read and QEMU process crash) by
    leveraging improper memory address validation.
    (bsc#1076114)

  - CVE-2018-7550: The multiboot functionality in Quick
    Emulator (aka QEMU) allowed local guest OS users to
    execute arbitrary code on the QEMU host via an
    out-of-bounds read or write memory access. (bsc#1083291)

  - CVE-2017-15124: VNC server implementation in Quick
    Emulator (QEMU) was found to be vulnerable to an
    unbounded memory allocation issue, as it did not
    throttle the framebuffer updates sent to its client. If
    the client did not consume these updates, VNC server
    allocates growing memory to hold onto this data. A
    malicious remote VNC client could use this flaw to cause
    DoS to the server host. (bsc#1073489) Additional bugs
    fixed :

  - Fix pcihp for 1.6 and older machine types (bsc#1074572)

  - Fix packaging dependencies (coreutils) for qemu-ksm
    package (bsc#1040202)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1068613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1070144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1073489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1074572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1076813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1083291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.qemu.org/2018/02/14/qemu-2-11-1-and-spectre-update/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15119/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15124/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-16845/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-17381/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-18043/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5715/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5683/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7550/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180762-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5676926a"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-516=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-516=1

SUSE CaaS Platform ALL:zypper in -t patch SUSE-CAASP-ALL-2018-516=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/22");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"qemu-block-rbd-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"qemu-x86-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"qemu-x86-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"s390x", reference:"qemu-s390-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"s390x", reference:"qemu-s390-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-block-curl-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-block-curl-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-block-iscsi-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-block-iscsi-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-block-ssh-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-block-ssh-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-debugsource-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-guest-agent-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-guest-agent-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-kvm-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-lang-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-tools-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qemu-tools-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qemu-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qemu-block-curl-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qemu-debugsource-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qemu-kvm-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qemu-tools-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.9.1-6.12.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qemu-x86-2.9.1-6.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
