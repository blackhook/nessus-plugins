#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0053-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(121060);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/27");

  script_cve_id("CVE-2018-15686", "CVE-2018-16864", "CVE-2018-16865");

  script_name(english:"SUSE SLES12 Security Update : systemd (SUSE-SU-2019:0053-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for systemd fixes the following issues :

Fix security vulnerabilities CVE-2018-16864 and CVE-2018-16865
(bsc#1120323): Both issues were memory corruptions via
attacker-controlled alloca which could have been used to gain root
privileges by a local attacker.

Fix security vulnerability CVE-2018-15686 (bsc#1113665): A
vulnerability in unit_deserialize of systemd used to allow an attacker
to supply arbitrary state across systemd re-execution via
NotifyAccess. This could have been used to improperly influence
systemd execution and possibly lead to root privilege escalation.

Remedy 2048 character line-length limit in systemd-sysctl code that
would cause parser failures if /etc/sysctl.conf contained lines that
exceeded this length (bsc#1071558).

Fix a bug in systemd's core timer code that would cause timer looping
under certain conditions, resulting in hundreds of syslog messages
being written to the journal (bsc#1068588).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1068588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1071558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1113665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-15686/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16864/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16865/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190053-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e406aea5");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2019-53=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15686");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgudev-1_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-GUdev-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgudev-1_0-0-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgudev-1_0-0-32bit-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgudev-1_0-0-debuginfo-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgudev-1_0-0-debuginfo-32bit-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgudev-1_0-devel-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libudev-devel-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libudev1-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libudev1-32bit-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libudev1-debuginfo-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libudev1-debuginfo-32bit-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"systemd-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"systemd-32bit-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"systemd-debuginfo-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"systemd-debuginfo-32bit-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"systemd-debugsource-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"systemd-devel-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"systemd-sysvinit-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"typelib-1_0-GUdev-1_0-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"udev-210-70.74.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"udev-debuginfo-210-70.74.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
