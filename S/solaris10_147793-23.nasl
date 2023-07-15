#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(124074);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/07");

  script_name(english:"Solaris 10 (sparc) : 147793-23");
  script_summary(english:"Check for patch 147793-23");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 147793-23"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: Kerberos patch.
Date this patch was last updated by Sun : Apr/15/19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/147793-23"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 147793-23 or higher");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140148");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140159");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:143937");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:144891");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146664");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:147715");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:147793");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148069");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148394");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148657");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151146");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (package_arch != "sparc") audit(AUDIT_ARCH_NOT, "sparc", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWcakr", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWgss", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWgssk", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWkdcu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWkrbu", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWrcmdc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWrcmds", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWtnetc", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"147793-23", obsoleted_by:"", package:"SUNWtnetd", version:"11.10.0,REV=2005.01.21.15.53") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWcakr / SUNWgss / SUNWgssk / SUNWhea / SUNWkdcu / SUNWkrbu / etc");
}
