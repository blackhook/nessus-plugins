#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2392-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(128992);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : util-linux / shadow (SUSE-SU-2019:2392-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for util-linux and shadow fixes the following issues :

util-linux :

Fixed an issue where PATH settings in /etc/default/su being ignored
(bsc#1121197)

Prevent outdated pam files (bsc#1082293).

Do not trim read-only volumes (bsc#1106214).

Integrate pam_keyinit pam module to login (bsc#1081947).

Perform one-time reset of /etc/default/su (bsc#1121197).

Fix problems in reading of login.defs values (bsc#1121197)

libmount: To prevent incorrect behavior, recognize more pseudofs and
netfs (bsc#1122417).

raw.service: Add RemainAfterExit=yes (bsc#1135534).

agetty: Return previous response of agetty for special characters
(bsc#1085196, bsc#1125886)

Fix /etc/default/su comments and create /etc/default/runuser
(bsc#1121197).

shadow: Fixed an issue where PATH settings in /etc/default/su being
ignored (bsc#1121197)

Hardening for su wrappers (bsc#353876)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1081947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1082293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1085196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1106214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=353876"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192392-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?378bbf91"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-2392=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2392=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2392=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2392=1"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libmount-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:shadow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:shadow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:shadow-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/18");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-libmount-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-libmount-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python-libmount-debugsource-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libblkid-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libblkid-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libblkid1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libblkid1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfdisk-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfdisk-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfdisk1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfdisk1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmount-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmount-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmount1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmount1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmartcols-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmartcols-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmartcols1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmartcols1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuuid-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuuid-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuuid1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuuid1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-libmount-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-libmount-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-libmount-debugsource-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"shadow-4.5-7.6.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"shadow-debuginfo-4.5-7.6.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"shadow-debugsource-4.5-7.6.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-debugsource-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-systemd-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-systemd-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-systemd-debugsource-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uuidd-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uuidd-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-libmount-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-libmount-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python-libmount-debugsource-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libblkid-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libblkid-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libblkid1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libblkid1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfdisk-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfdisk-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfdisk1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfdisk1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmount-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmount-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmount1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmount1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmartcols-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmartcols-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmartcols1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmartcols1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuuid-devel-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuuid-devel-static-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuuid1-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuuid1-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-libmount-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-libmount-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-libmount-debugsource-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"shadow-4.5-7.6.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"shadow-debuginfo-4.5-7.6.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"shadow-debugsource-4.5-7.6.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-debugsource-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-systemd-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-systemd-debuginfo-2.31.1-9.8.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-systemd-debugsource-2.31.1-9.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux / shadow");
}
