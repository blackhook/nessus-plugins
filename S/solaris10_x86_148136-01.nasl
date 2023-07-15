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
  script_id(108142);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 10 (x86) : 148136-01");
  script_summary(english:"Check for patch 148136-01");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 148136-01"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunVTS 7.0_x86: Patch Set 14 consolidation.
Date this patch was last updated by Sun : Apr/30/12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/148136-01"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 148136-01 or higher");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:137818");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138414");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138505");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139172");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139657");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:142139");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:143007");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:143978");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:144735");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:145112");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146862");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:147447");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:147936");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148136");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/30");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148136-01", obsoleted_by:"151266-01 150585-01 149896-01 151673-01 149396-01 ", package:"SUNWvts", version:"7.0,REV=2008.02.15.15.25") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148136-01", obsoleted_by:"151266-01 150585-01 149896-01 151673-01 149396-01 ", package:"SUNWvtss", version:"7.0,REV=2008.02.07.18.55") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148136-01", obsoleted_by:"151266-01 150585-01 149896-01 151673-01 149396-01 ", package:"SUNWvtsts", version:"7.0,REV=2008.02.15.15.25") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWvts / SUNWvtss / SUNWvtsts");
}
