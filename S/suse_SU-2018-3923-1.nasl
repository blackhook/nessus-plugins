#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3923-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(119283);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-1059");

  script_name(english:"SUSE SLES12 Security Update : dpdk (SUSE-SU-2018:3923-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for dpdk to version 16.11.8 provides the following
security fix :

CVE-2018-1059: restrict untrusted guest to misuse virtio to corrupt
host application (ovs-dpdk) memory which could have lead all VM to
lose connectivity (bsc#1089638)

and following non-security fixes: Enable the broadcom chipset family
Broadcom NetXtreme II BCM57810 (bsc#1073363)

Fix a latency problem by using cond_resched rather than
schedule_timeout_interruptible (bsc#1069601)

Fix a syntax error affecting csh environment configuration
(bsc#1102310)

Fixes in net/bnxt :

  - Fix HW Tx checksum offload check

  - Fix incorrect IO address handling in Tx

  - Fix Rx ring count limitation

  - Check access denied for HWRM commands

  - Fix RETA size

  - Fix close operation

Fixes in eal/linux :

  - Fix an invalid syntax in interrupts

  - Fix return codes on thread naming failure

Fixes in kni :

  - Fix crash with null name

  - Fix build with gcc 8.1

Fixes in net/thunderx :

  - Fix build with gcc optimization on

  - Avoid sq door bell write on zero packet

net/bonding: Fix MAC address reset

vhost: Fix missing increment of log cache count

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1069601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1073363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1089638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1059/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183923-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6889f865"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2795=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2795=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dpdk-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/29");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"dpdk-16.11.8-8.10.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"dpdk-debuginfo-16.11.8-8.10.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"dpdk-debugsource-16.11.8-8.10.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"dpdk-kmp-default-16.11.8_k4.4.156_94.64-8.10.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"dpdk-kmp-default-debuginfo-16.11.8_k4.4.156_94.64-8.10.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"dpdk-tools-16.11.8-8.10.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dpdk");
}
