#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53528);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2010-3332", "CVE-2010-4159");

  script_name(english:"SuSE 11.1 Security Update : Mono (SAT Patch Number 4260)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security bugs have been fixed :

  - Mono was vulnerable to a padding oracle attack.
    (CVE-2010-3332)

  - Mono loaded shared libraries from the current directory.
    (CVE-2010-4159)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3332.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4159.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 4260.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bytefx-data-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-data-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"bytefx-data-mysql-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"ibm-data-db2-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-core-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-data-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-data-firebird-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-data-oracle-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-data-postgresql-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-data-sqlite-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-data-sybase-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-devel-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-extras-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-jscript-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-locale-extras-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-nunit-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-web-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mono-winforms-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"bytefx-data-mysql-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"ibm-data-db2-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-core-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-data-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-data-firebird-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-data-oracle-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-data-postgresql-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-data-sqlite-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-data-sybase-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-devel-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-extras-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-jscript-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-locale-extras-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-nunit-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-web-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mono-winforms-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mono-core-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mono-data-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mono-data-postgresql-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mono-data-sqlite-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mono-locale-extras-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mono-nunit-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mono-web-2.0.1-1.34.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mono-winforms-2.0.1-1.34.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
