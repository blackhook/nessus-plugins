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
  script_id(64118);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-3382");

  script_name(english:"SuSE 11.2 Security Update : Mono (SAT Patch Number 6543)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mono was updated to fix a cross-site scripting attack in the
System.Web class 'forbidden extensions' filtering has been fixed.
(CVE-2012-3382)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3382.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6543.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-wcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:monodoc-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"bytefx-data-mysql-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"ibm-data-db2-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-core-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-data-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-data-firebird-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-data-oracle-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-data-postgresql-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-data-sqlite-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-data-sybase-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-devel-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-extras-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-jscript-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-locale-extras-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-nunit-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-wcf-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-web-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mono-winforms-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"monodoc-core-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"bytefx-data-mysql-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"ibm-data-db2-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-core-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-data-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-data-firebird-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-data-oracle-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-data-postgresql-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-data-sqlite-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-data-sybase-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-devel-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-extras-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-jscript-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-locale-extras-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-nunit-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-wcf-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-web-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mono-winforms-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"monodoc-core-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mono-core-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mono-data-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mono-data-postgresql-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mono-data-sqlite-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mono-locale-extras-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mono-nunit-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mono-web-2.6.7-0.9.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mono-winforms-2.6.7-0.9.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
