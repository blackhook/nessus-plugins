#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50910);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-1570", "CVE-2009-3909");

  script_name(english:"SuSE 11 Security Update : gimp (SAT Patch Number 2155)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Integer overflows in the BMP and PSD plug-ins potentially allowed
attackers to execute arbitrary code on the victim's system by tricking
the victim to open specially crafted files. (CVE-2009-1570 /
CVE-2009-3909)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=555144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=555166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3909.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2155.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gimp-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gimp-plugins-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"gimp-2.6.2-3.28.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"gimp-lang-2.6.2-3.28.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"gimp-plugins-python-2.6.2-3.28.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gimp-2.6.2-3.28.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gimp-lang-2.6.2-3.28.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gimp-plugins-python-2.6.2-3.28.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
