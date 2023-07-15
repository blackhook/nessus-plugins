#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108086);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-4643");

  script_name(english:"Solaris 10 (x86) : 146567-01");
  script_summary(english:"Check for patch 146567-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 146567-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Oracle Open Office 3.3 Service Pack 1 (Solaris_x86, Multilanguages.
Date this patch was last updated by Sun : Mar/10/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/146567-01"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 146567-01");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146567");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris/showrev");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

showrev = get_kb_item("Host/Solaris/showrev");
if (empty_or_null(showrev)) audit(AUDIT_OS_NOT, "Solaris");
os_ver = pregmatch(pattern:"Release: (\d+.(\d+))", string:showrev);
if (empty_or_null(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Solaris");
full_ver = os_ver[1];
os_level = os_ver[2];
if (full_ver != "5.10") audit(AUDIT_OS_NOT, "Solaris 10", "Solaris " + os_level);
package_arch = pregmatch(pattern:"Application architecture: (\w+)", string:showrev);
if (empty_or_null(package_arch)) audit(AUDIT_UNKNOWN_ARCH);
package_arch = package_arch[1];
if (package_arch != "i386") audit(AUDIT_ARCH_NOT, "i386", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-ar-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-core01", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-core03", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-core04", version:"3.3.0,REV=7.2010.11.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-core05", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-de-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-en-US-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-es-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-fr-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-hu-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-it-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-ja-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-ko-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-math", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-nl-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-pl-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-pt-BR-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-pt-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-ru-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-sv-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-writer", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-zh-CN-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"ooobasis33-zh-TW-calc", version:"3.3.0,REV=7.2010.11.23") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"146567-01", obsoleted_by:"", package:"openofficeorg-ure", version:"1.7.0,REV=7.2010.11.23") < 0) flag++;

if (flag) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : solaris_get_report()
  );
} else {
  patch_fix = solaris_patch_fix_get();
  if (!empty_or_null(patch_fix)) audit(AUDIT_PATCH_INSTALLED, patch_fix, "Solaris 10");
  tested = solaris_pkg_tests_get();
  if (!empty_or_null(tested)) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "ooobasis33-ar-calc / ooobasis33-calc / ooobasis33-core01 / etc");
}
