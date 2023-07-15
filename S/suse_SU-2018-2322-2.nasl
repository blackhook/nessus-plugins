#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2322-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(118279);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/04");

  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12368", "CVE-2018-5156", "CVE-2018-5188");

  script_name(english:"SUSE SLES12 Security Update : MozillaFirefox (SUSE-SU-2018:2322-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for MozillaFirefox to version ESR 52.9 fixes the following
issues :

CVE-2018-5188: Various memory safety bugs (bsc#1098998)

CVE-2018-12368: No warning when opening executable SettingContent-ms
files

CVE-2018-12366: Invalid data handling during QCMS transformations

CVE-2018-12365: Compromised IPC child process can list local filenames

CVE-2018-12364: CSRF attacks through 307 redirects and NPAPI plugins

CVE-2018-12363: Use-after-free when appending DOM nodes

CVE-2018-12362: Integer overflow in SSSE3 scaler

CVE-2018-12360: Use-after-free when using focus()

CVE-2018-5156: Media recorder segmentation fault when track type is
changed during capture

CVE-2018-12359: Buffer overflow using computed size of canvas element

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12359/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12360/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12362/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12363/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12364/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12365/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12366/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-12368/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5156/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-5188/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182322-2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c41edc0d"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2018-1560=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12368");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-52.9.0esr-109.38.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.9.0esr-109.38.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.9.0esr-109.38.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-devel-52.9.0esr-109.38.2")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSRF', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
