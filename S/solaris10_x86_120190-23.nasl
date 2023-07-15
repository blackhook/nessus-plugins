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
  script_id(107858);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-2198", "CVE-2006-3117", "CVE-2006-5870", "CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239", "CVE-2007-0245", "CVE-2007-1466", "CVE-2007-2754", "CVE-2007-2834", "CVE-2007-4575", "CVE-2010-4253");

  script_name(english:"Solaris 10 (x86) : 120190-23");
  script_summary(english:"Check for patch 120190-23");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 120190-23"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"StarSuite 8 (Solaris_x86): Update 18.
Date this patch was last updated by Sun : Mar/15/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/120190-23"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 120190-23");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:120190");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/15");
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
if (package_arch != "i86pc") audit(AUDIT_ARCH_NOT, "i86pc", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-base", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-calc", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core01", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core02", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core03", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core04", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core05", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core06", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core07", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core08", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-core09", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-draw", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-gnome-integration", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-graphicfilter", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-impress", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-ja-fonts", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-ja-help", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-ja-res", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-ja", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-javafilter", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-ko-help", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-ko-res", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-ko", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-lngutils", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-math", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-onlineupdate", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-sunsearchtoolbar", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-writer", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-xsltfilter", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-zh-CN-help", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-zh-CN-res", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-zh-CN", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-zh-TW-help", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-zh-TW-res", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i86pc", patch:"120190-23", obsoleted_by:"", package:"SUNWstarsuite-zh-TW", version:"8.0.0,REV=106.2005.05.26") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWstarsuite-base / SUNWstarsuite-calc / SUNWstarsuite-core01 / etc");
}
