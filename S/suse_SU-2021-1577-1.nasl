#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1577-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149458);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/24");

  script_cve_id("CVE-2018-7544", "CVE-2020-11810", "CVE-2020-15078");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : openvpn (SUSE-SU-2021:1577-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openvpn fixes the following issues :

CVE-2020-15078: Fixed authentication bypass with deferred
authentication (bsc#1185279).

CVE-2020-11810: Fixed race condition between allocating peer-id and
initializing data channel key (bsc#1169925).

CVE-2018-7544: Fixed cross-protocol scripting issue that was
discovered in the management interface (bsc#1085803).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1085803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1169925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1185279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7544/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-11810/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-15078/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211577-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b62fa32"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-1577=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1577=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7544");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-auth-pam-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-auth-pam-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");
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
if (rpm_check(release:"SLES15", sp:"3", reference:"openvpn-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"openvpn-auth-pam-plugin-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"openvpn-auth-pam-plugin-debuginfo-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"openvpn-debuginfo-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"openvpn-debugsource-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"openvpn-devel-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvpn-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvpn-auth-pam-plugin-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvpn-auth-pam-plugin-debuginfo-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvpn-debuginfo-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvpn-debugsource-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvpn-devel-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"openvpn-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"openvpn-auth-pam-plugin-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"openvpn-auth-pam-plugin-debuginfo-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"openvpn-debuginfo-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"openvpn-debugsource-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"openvpn-devel-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openvpn-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openvpn-auth-pam-plugin-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openvpn-auth-pam-plugin-debuginfo-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openvpn-debuginfo-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openvpn-debugsource-2.4.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openvpn-devel-2.4.3-5.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn");
}
