#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1654-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149796);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-3516",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libxml2 (SUSE-SU-2021:1654-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libxml2 fixes the following issues :

CVE-2021-3537: NULL pointer dereference in
valid.c:xmlValidBuildAContentModel (bsc#1185698)

CVE-2021-3518: Fixed a use after free in
xinclude.c:xmlXIncludeDoProcess (bsc#1185408).

CVE-2021-3517: Fixed a heap-based buffer overflow in
entities.c:xmlEncodeEntitiesInternal (bsc#1185410).

CVE-2021-3516: Fixed a use after free in
entities.c:xmlEncodeEntitiesInternal (bsc#1185409).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1185408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1185409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1185410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1185698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3516/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3517/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3518/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3537/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211654-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e70541a");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE MicroOS 5.0 :

zypper in -t patch SUSE-SUSE-MicroOS-5.0-2021-1654=1

SUSE Linux Enterprise Module for Python2 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Python2-15-SP3-2021-1654=1

SUSE Linux Enterprise Module for Python2 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Python2-15-SP2-2021-1654=1

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-1654=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1654=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-libxml2-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-libxml2-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-libxml2-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libxml2-2-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libxml2-2-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libxml2-debugsource-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libxml2-devel-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libxml2-tools-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libxml2-tools-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python-libxml2-python-debugsource-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python2-libxml2-python-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python2-libxml2-python-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-libxml2-python-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"python3-libxml2-python-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libxml2-2-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libxml2-2-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libxml2-debugsource-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libxml2-devel-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libxml2-tools-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libxml2-tools-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python-libxml2-python-debugsource-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python2-libxml2-python-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python2-libxml2-python-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-libxml2-python-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-libxml2-python-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libxml2-2-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libxml2-2-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libxml2-debugsource-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libxml2-devel-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libxml2-tools-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libxml2-tools-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python-libxml2-python-debugsource-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python2-libxml2-python-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python2-libxml2-python-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-libxml2-python-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"python3-libxml2-python-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libxml2-2-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libxml2-2-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libxml2-debugsource-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libxml2-devel-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libxml2-tools-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libxml2-tools-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python-libxml2-python-debugsource-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python2-libxml2-python-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python2-libxml2-python-debuginfo-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-libxml2-python-2.9.7-3.34.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-libxml2-python-debuginfo-2.9.7-3.34.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2");
}
