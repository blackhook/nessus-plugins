#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0503-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(146600);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/02");

  script_cve_id("CVE-2020-8625");

  script_name(english:"SUSE SLES12 Security Update : bind (SUSE-SU-2021:0503-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for bind fixes the following issues :

CVE-2020-8625: A vulnerability in BIND's GSSAPI security policy
negotiation can be targeted by a buffer overflow attack [bsc#1182246,
CVE-2020-8625]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1182246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-8625/"
  );
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210503-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15709a66"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 9 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-9-2021-503=1

SUSE OpenStack Cloud 9 :

zypper in -t patch SUSE-OpenStack-Cloud-9-2021-503=1

SUSE Linux Enterprise Software Development Kit 12-SP5 :

zypper in -t patch SUSE-SLE-SDK-12-SP5-2021-503=1

SUSE Linux Enterprise Server for SAP 12-SP4 :

zypper in -t patch SUSE-SLE-SAP-12-SP4-2021-503=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-503=1

SUSE Linux Enterprise Server 12-SP4-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-LTSS-2021-503=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8625");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libbind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libbind9-161-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns1110");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns1110-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libirs161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libirs161-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisc1107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisc1107-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisccc161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisccc161-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisccfg163");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libisccfg163-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblwres161");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblwres161-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"bind-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"bind-chrootenv-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"bind-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"bind-debugsource-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"bind-utils-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"bind-utils-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libbind9-161-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libbind9-161-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdns1110-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libdns1110-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libirs161-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libirs161-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libisc1107-32bit-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libisc1107-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libisc1107-debuginfo-32bit-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libisc1107-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libisccc161-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libisccc161-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libisccfg163-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libisccfg163-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"liblwres161-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"liblwres161-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bind-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bind-chrootenv-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bind-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bind-debugsource-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bind-utils-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"bind-utils-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libbind9-161-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libbind9-161-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libdns1110-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libdns1110-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libirs161-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libirs161-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libisc1107-32bit-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libisc1107-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libisc1107-debuginfo-32bit-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libisc1107-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libisccc161-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libisccc161-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libisccfg163-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"libisccfg163-debuginfo-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"liblwres161-9.11.22-3.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"liblwres161-debuginfo-9.11.22-3.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
