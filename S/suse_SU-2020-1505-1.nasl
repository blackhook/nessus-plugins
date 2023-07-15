#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1505-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(137551);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/23");

  script_cve_id("CVE-2020-11736");

  script_name(english:"SUSE SLES12 Security Update : file-roller (SUSE-SU-2020:1505-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for file-roller fixes the following issues :

Security issue fixed :

CVE-2020-11736: Fixed a directory traversal vulnerability due to
improper checking whether a file's parent is an external symlink
(bsc#1169428).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1169428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2020-11736/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201505-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97f37e6f"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-1505=1

SUSE Linux Enterprise Server 12-SP4 :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-2020-1505=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11736");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-roller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-roller-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:file-roller-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nautilus-file-roller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nautilus-file-roller-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SLES12", sp:"4", reference:"file-roller-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"file-roller-debuginfo-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"file-roller-debugsource-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"nautilus-file-roller-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"nautilus-file-roller-debuginfo-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"file-roller-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"file-roller-debuginfo-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"file-roller-debugsource-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"nautilus-file-roller-3.20.3-15.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"nautilus-file-roller-debuginfo-3.20.3-15.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file-roller");
}
