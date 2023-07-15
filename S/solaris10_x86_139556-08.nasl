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
  script_id(108015);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 10 (x86) : 139556-08");
  script_summary(english:"Check for patch 139556-08");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 139556-08"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: Kernel Patch.
Date this patch was last updated by Sun : May/07/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/139556-08"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 139556-08");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:120063");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:125552");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:126265");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:127736");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:127744");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:127754");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:127854");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:128034");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:128297");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:128323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:128341");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:128407");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137096");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137122");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137279");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137281");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137293");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138043");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138049");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138059");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138099");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138107");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138113");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138115");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138117");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138119");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138232");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138242");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138412");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138628");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138849");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138851");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138859");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138862");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138871");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138889");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139391");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139467");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139484");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139488");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139493");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139499");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139507");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139513");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139552");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139556");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139561");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139567");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139573");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139575");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139580");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140143");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140193");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140195");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140198");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140335");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140410");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140414");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140678");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140680");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140777");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140856");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:141007");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:141009");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWarc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWarcr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWauda", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWbtool", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcpcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcsd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcslr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcsr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWcsu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWdoc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWdtrc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWdtrp", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWfmd", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWfmdr", version:"11.10.0,REV=2006.03.29.01.57") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWgrub", version:"11.10.0,REV=2005.09.03.12.22") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWgrubS", version:"11.10.0,REV=2005.09.14.10.55") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWhermon", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWib", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWibsdpib", version:"11.10.0,REV=2008.02.29.14.37") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWintgige", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWipfh", version:"11.10.0,REV=2006.05.09.20.40") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWipfu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWiscsitgtr", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWiscsitgtu", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWloc", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWlxr", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWlxu", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWmdb", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWmdbr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWnfsckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWnisu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWnxge", version:"11.10.0,REV=2007.07.08.17.21") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWos86r", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWpapi", version:"11.10.0,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWpcu", version:"13.1,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWpool", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWppm", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWpsm-lpd", version:"11.10.0,REV=2005.01.08.01.09") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWpsu", version:"13.1,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWrds", version:"11.10.0,REV=2007.06.20.13.12") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWroute", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWsadmi", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWsmapi", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWtavor", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWtoo", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWudapltu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWudaplu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWudfr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWxcu4", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWzfskr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWzfsr", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWzfsu", version:"11.10.0,REV=2006.05.18.01.46") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"139556-08", obsoleted_by:"", package:"SUNWzoneu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWarc / SUNWarcr / SUNWauda / SUNWbtool / SUNWcakr / SUNWckr / etc");
}
