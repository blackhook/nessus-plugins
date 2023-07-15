#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2956-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130954);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-12207", "CVE-2018-20126", "CVE-2019-11135", "CVE-2019-12068");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qemu (SUSE-SU-2019:2956-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for qemu fixes the following issues :

Remove a backslash '\' escape character from 80-qemu-ga.rules
(bsc#1153358) Unlike sles 15 or newer guests, The udev rule file of
qemu guest agent in sles 12 sp4 or newer guest only needs one escape
character.

Fix use-after-free in slirp (CVE-2018-20126 bsc#1119991)

Fix potential DOS in lsi scsi controller emulation (CVE-2019-12068
bsc#1146873)

Expose taa-no 'feature', indicating CPU does not have the TSX Async
Abort vulnerability. (CVE-2019-11135 bsc#1152506)

Expose pschange-mc-no 'feature', indicating CPU does not have the page
size change machine check vulnerability (CVE-2018-12207 bsc#1155812)

Patch queue updated from
https://gitlab.suse.de/virtualization/qemu.git SLE12-SP4

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1146873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://gitlab.suse.de/virtualization/qemu.git"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12207/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20126/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11135/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12068/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192956-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f81dc69"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-2956=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-2956=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11135");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"qemu-block-rbd-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"qemu-x86-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"s390x", reference:"qemu-s390-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"s390x", reference:"qemu-s390-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-curl-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-curl-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-iscsi-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-iscsi-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-ssh-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-block-ssh-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-debugsource-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-guest-agent-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-guest-agent-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-kvm-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-lang-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-tools-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"qemu-tools-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-block-curl-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-debugsource-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-kvm-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-tools-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.11.2-5.23.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"qemu-x86-2.11.2-5.23.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
