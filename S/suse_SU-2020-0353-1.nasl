#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0353-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133547);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-1712");

  script_name(english:"SUSE SLES12 Security Update : systemd (SUSE-SU-2020:0353-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for systemd provides the following fixes :

CVE-2020-1712 (bsc#bsc#1162108) Fix a heap use-after-free
vulnerability, when asynchronous Polkit queries were performed while
handling Dbus messages. A local unprivileged attacker could have
abused this flaw to crash systemd services or potentially execute code
and elevate their privileges, by sending specially crafted Dbus
messages.

sd-bus: Deal with cookie overruns. (bsc#1150595)

rules: Add by-id symlinks for persistent memory. (bsc#1140631)

Drop the old fds used for logging and reopen them in the sub process
before doing any new logging. (bsc#1154948)

Fix warnings thrown during package installation (bsc#1154043)

Fix for systemctl hanging by restart. (bsc#1139459)

man: mention that alias names are only effective after 'systemctl
enable'. (bsc#1151377)

ask-password: improve log message when inotify limit is reached.
(bsc#1155574)

udevd: wait for workers to finish when exiting. (bsc#1106383)

core: fragments of masked units ought not be considered for
NeedDaemonReload. (bsc#1156482)

udev: fix 'NULL' deref when executing rules. (bsc#1151506)

Introduce function for reading virtual files in 'sysfs' and 'procfs'.
(bsc#1133495, bsc#1159814)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1127557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1139459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1150595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1151506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1155574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1156482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1159814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1162108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-1712/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200353-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ccac0771"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2020-353=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-353=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1712");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsystemd0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/07");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"5", reference:"libsystemd0-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libsystemd0-32bit-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libsystemd0-debuginfo-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libsystemd0-debuginfo-32bit-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libudev1-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libudev1-32bit-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libudev1-debuginfo-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libudev1-debuginfo-32bit-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"systemd-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"systemd-32bit-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"systemd-debuginfo-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"systemd-debuginfo-32bit-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"systemd-debugsource-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"systemd-sysvinit-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"udev-228-157.9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"udev-debuginfo-228-157.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
