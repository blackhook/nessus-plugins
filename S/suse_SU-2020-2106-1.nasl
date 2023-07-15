#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2106-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(139309);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-16746", "CVE-2019-20908", "CVE-2020-0305", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10769", "CVE-2020-10773", "CVE-2020-12771", "CVE-2020-12888", "CVE-2020-13974", "CVE-2020-14416", "CVE-2020-15393", "CVE-2020-15780");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2020:2106-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The SUSE Linux Enterprise 15 GA LTSS kernel was updated to receive
various security and bugfixes.

The following security bugs were fixed :

CVE-2020-0305: In cdev_get of char_dev.c, there is a possible
use-after-free due to a race condition. This could lead to local
escalation of privilege with System execution privileges needed. User
interaction is not needed for exploitation (bnc#1174462).

CVE-2019-20908: An issue was discovered in drivers/firmware/efi/efi.c
where incorrect access permissions for the efivar_ssdt ACPI variable
could be used by attackers to bypass lockdown or secure boot
restrictions, aka CID-1957a85b0032 (bnc#1173567).

CVE-2020-15780: An issue was discovered in
drivers/acpi/acpi_configfs.c where injection of malicious ACPI tables
via configfs could be used by attackers to bypass lockdown and secure
boot restrictions, aka CID-75b0cea7bf30 (bnc#1173573).

CVE-2020-15393: usbtest_disconnect in drivers/usb/misc/usbtest.c had a
memory leak, aka CID-28ebeb8db770 (bnc#1173514).

CVE-2020-12771: btree_gc_coalesce in drivers/md/bcache/btree.c has a
deadlock if a coalescing operation fails (bnc#1171732).

CVE-2019-16746: An issue was discovered in net/wireless/nl80211.c
which did not check the length of variable elements in a beacon head,
leading to a buffer overflow (bnc#1152107 1173659).

CVE-2020-12888: The VFIO PCI driver mishandled attempts to access
disabled memory space (bnc#1171868).

CVE-2020-10769: A buffer over-read flaw was found in
crypto_authenc_extractkeys in crypto/authenc.c in the IPsec
Cryptographic algorithm's module, authenc. When a payload longer than
4 bytes, and is not following 4-byte alignment boundary guidelines, it
causes a buffer over-read threat, leading to a system crash. This flaw
allowed a local attacker with user privileges to cause a denial of
service (bnc#1173265).

CVE-2020-10773: A kernel stack information leak on s390/s390x was
fixed (bnc#1172999).

CVE-2020-14416: A race condition in tty->disc_data handling in the
slip and slcan line discipline could lead to a use-after-free, aka
CID-0ace17d56824. This affects drivers/net/slip/slip.c and
drivers/net/can/slcan.c (bnc#1162002).

CVE-2020-10768: Indirect branch speculation could have been enabled
after it was force-disabled by the PR_SPEC_FORCE_DISABLE prctl
command. (bnc#1172783).

CVE-2020-10766: Fixed Rogue cross-process SSBD shutdown, where a Linux
scheduler logical bug allows an attacker to turn off the SSBD
protection. (bnc#1172781).

CVE-2020-10767: Indirect Branch Prediction Barrier was force-disabled
when STIBP is unavailable or enhanced IBRS is available.
(bnc#1172782).

CVE-2020-13974: drivers/tty/vt/keyboard.c had an integer overflow if
k_ascii is called several times in a row, aka CID-b86dab054059
(bnc#1172775).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1051510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1065729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1071995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1158755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1170011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1171868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1172999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1173999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1174543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-16746/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-20908/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-0305/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10766/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10767/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10768/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10769/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-10773/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12771/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-12888/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-13974/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-14416/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15393/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15780/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202106-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef3c057c"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-2106=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-2106=1

SUSE Linux Enterprise Module for Live Patching 15 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-2020-2106=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2106=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-2106=1

SUSE Linux Enterprise High Availability 15 :

zypper in -t patch SUSE-SLE-Product-HA-15-2020-2106=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16746");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-base-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-debuginfo-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-debugsource-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-devel-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-devel-debuginfo-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-default-man-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-obs-build-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-obs-build-debugsource-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-syms-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-base-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-base-debuginfo-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-debuginfo-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-vanilla-debugsource-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"reiserfs-kmp-default-4.12.14-150.55.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"reiserfs-kmp-default-debuginfo-4.12.14-150.55.1")) flag++;


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
