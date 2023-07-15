#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2485-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(119551);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/10 13:51:48");

  script_cve_id("CVE-2018-10583");

  script_name(english:"SUSE SLED12 Security Update : libreoffice (SUSE-SU-2018:2485-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libreoffice to 6.0.5.2 fixes the following issues :

Security issues fixed :

CVE-2018-10583: An information disclosure vulnerability occurs during
automatic processing and initiating an SMB connection embedded in a
malicious file, as demonstrated by
xlink:href=file://192.168.0.2/test.jpg within an
office:document-content element in a .odt XML document. (bsc#1091606)

Non security issues fixed: Bugfix: Table borders appear black in
LibreOffice (while white in PowerPoint) (bsc#1088262)

Bugfix: LibreOffice extension 'Language Tool' fails after Tumbleweed
update (bsc#1050305)

Bugfix: libreoffice-gnome can no longer be installed in parallel to
libreoffice-gtk3 as there is a potential file conflict (bsc#1096673)

Bugfix: LibreOffice Writer: Text in boxes were not visible
(bsc#1094359)

Use libreoffice-gtk3 if xfce is present (bsc#1092699)

Various other bug fixes

Exporting to PPTX results in vertical labels being shown horizontally
(bsc#1095639)

Table in PPTX misplaced and partly blue (bsc#1098891)

Labels in chart change (from white and other colors) to black when
saving as PPTX (bsc#1088263)

Exporting to PPTX shifts arrow shapes quite a bit bsc#1095601

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1050305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1088263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1091772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1092699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1094359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1095639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1096673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10583/"
  );
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182485-2/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7dcdf87"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2018-1748=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2018-1748=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2018-1748=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-base-drivers-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-calc-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-draw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-filters-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-impress-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-math-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-officebean-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-pyuno-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libreoffice-writer-extensions");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-drivers-mysql-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-base-drivers-postgresql-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-calc-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-calc-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-calc-extensions-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-debugsource-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-draw-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-draw-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-filters-optional-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-gnome-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-gnome-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-gtk2-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-gtk2-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-impress-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-impress-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-mailmerge-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-math-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-math-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-officebean-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-officebean-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-pyuno-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-pyuno-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-writer-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-writer-debuginfo-6.0.5.2-43.38.5")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libreoffice-writer-extensions-6.0.5.2-43.38.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreoffice");
}
