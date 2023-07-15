#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0563-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(146797);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/01");

  script_cve_id("CVE-2021-26720");

  script_name(english:"SUSE SLES12 Security Update : avahi (SUSE-SU-2021:0563-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for avahi fixes the following issues :

CVE-2021-26720: drop privileges when invoking
avahi-daemon-check-dns.sh (bsc#1180827)

Add sudo to requires: used to drop privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1180827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2021-26720/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210563-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b7c4425"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP5 :

zypper in -t patch SUSE-SLE-WE-12-SP5-2021-563=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-563=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-563=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26720");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-core7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns_sd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/24");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"5", reference:"avahi-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"avahi-debuginfo-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"avahi-debuginfo-32bit-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"avahi-debugsource-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"avahi-glib2-debugsource-0.6.32-32.12.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"avahi-utils-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"avahi-utils-debuginfo-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-client3-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-client3-32bit-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-client3-debuginfo-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-client3-debuginfo-32bit-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-common3-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-common3-32bit-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-common3-debuginfo-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-common3-debuginfo-32bit-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-core7-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-core7-debuginfo-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-glib1-0.6.32-32.12.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-glib1-32bit-0.6.32-32.12.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-glib1-debuginfo-0.6.32-32.12.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libavahi-glib1-debuginfo-32bit-0.6.32-32.12.3")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libdns_sd-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libdns_sd-32bit-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libdns_sd-debuginfo-0.6.32-32.12.2")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libdns_sd-debuginfo-32bit-0.6.32-32.12.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi");
}
