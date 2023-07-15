#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1755-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149976);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/01");

  script_cve_id("CVE-2018-20340", "CVE-2019-9578");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libu2f-host (SUSE-SU-2021:1755-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libu2f-host fixes the following issues :

This update ships the u2f-host package (jsc#ECO-3687 bsc#1184648)

Version 1.1.10 (released 2019-05-15)

Add new devices to udev rules.

Fix a potentially uninitialized buffer (CVE-2019-9578, bsc#1128140)

Version 1.1.9 (released 2019-03-06)

Fix CID copying from the init response, which broke compatibility with
some devices.

Version 1.1.8 (released 2019-03-05)

Add udev rules

Drop 70-old-u2f.rules and use 70-u2f.rules for everything

Use a random nonce for setting up CID to prevent fingerprinting

CVE-2019-9578: Parse the response to init in a more stable way to
prevent leakage of uninitialized stack memory back to the device
(bsc#1128140).

Version 1.1.7 (released 2019-01-08)

Fix for trusting length from device in device init.

Fix for buffer overflow when receiving data from device. (YSA-2019-01,
CVE-2018-20340, bsc#1124781)

Add udev rules for some new devices.

Add udev rule for Feitian ePass FIDO

  - Add a timeout to the register and authenticate actions.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1128140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1184648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20340/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9578/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211755-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4095e28"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-1755=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1755=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20340");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libu2f-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libu2f-host-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libu2f-host-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libu2f-host0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libu2f-host0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:u2f-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:u2f-host-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"3", reference:"libu2f-host-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libu2f-host-debugsource-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libu2f-host-devel-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libu2f-host0-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libu2f-host0-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"u2f-host-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"u2f-host-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libu2f-host-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libu2f-host-debugsource-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libu2f-host-devel-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libu2f-host0-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libu2f-host0-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"u2f-host-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"u2f-host-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libu2f-host-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libu2f-host-debugsource-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libu2f-host-devel-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libu2f-host0-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libu2f-host0-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"u2f-host-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"u2f-host-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libu2f-host-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libu2f-host-debugsource-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libu2f-host-devel-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libu2f-host0-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libu2f-host0-debuginfo-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"u2f-host-1.1.10-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"u2f-host-debuginfo-1.1.10-3.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libu2f-host");
}
