#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2907-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117823);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10902", "CVE-2018-10940", "CVE-2018-14634", "CVE-2018-14734", "CVE-2018-15572", "CVE-2018-16658", "CVE-2018-6554", "CVE-2018-6555");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2018:2907-1)");
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

The following security bugs were fixed :

CVE-2018-14634: Prevent integer overflow in create_elf_tables that
allowed a local attacker to exploit this vulnerability via a SUID-root
binary and obtain full root privileges (bsc#1108912).

CVE-2018-10940: The cdrom_ioctl_media_changed function allowed local
attackers to use a incorrect bounds check in the CDROM driver
CDROM_MEDIA_CHANGED ioctl to read out kernel memory (bsc#1092903)

CVE-2018-16658: Prevent information leak in cdrom_ioctl_drive_status
that could have been used by local attackers to read kernel memory
(bnc#1107689)

CVE-2018-6555: The irda_setsockopt function allowed local users to
cause a denial of service (ias_object use-after-free and system crash)
or possibly have unspecified other impact via an AF_IRDA socket
(bnc#1106511)

CVE-2018-6554: Prevent memory leak in the irda_bind function that
allowed local users to cause a denial of service (memory consumption)
by repeatedly binding an AF_IRDA socket (bnc#1106509)

CVE-2018-15572: The spectre_v2_select_mitigation function did not
always fill RSB upon a context switch, which made it easier for
attackers to conduct userspace-userspace spectreRSB attacks
(bnc#1102517)

CVE-2018-10902: Protect against concurrent access to prevent double
realloc (double free) in snd_rawmidi_input_params() and
snd_rawmidi_output_status(). A malicious local attacker could have
used this for privilege escalation (bnc#1105322).

CVE-2018-14734: ucma_leave_multicast accessed a certain data structure
after a cleanup step in ucma_process_join, which allowed attackers to
cause a denial of service (use-after-free) (bsc#1103119).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1102517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1103119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1104818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1105536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1107689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1108912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10902/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10940/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14634/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-14734/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-15572/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16658/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6554/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6555/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182907-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c4a9462"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-kernel-13799=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-13799=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-kernel-13799=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-kernel-13799=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/28");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.106.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.106.50.1")) flag++;


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
