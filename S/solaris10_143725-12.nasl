#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(124073);
  script_version("1.2");
  script_cvs_date("Date: 2020/01/07");

  script_name(english:"Solaris 10 (sparc) : 143725-12");
  script_summary(english:"Check for patch 143725-12");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 143725-12"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10: SunFreeware ntp patch.
Date this patch was last updated by Sun : Apr/15/19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/143725-12"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 143725-12 or higher");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:143725");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:143727");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"143725-12", obsoleted_by:"", package:"SUNWntp4S", version:"11.10.0,REV=2009.07.02.14.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"143725-12", obsoleted_by:"", package:"SUNWntp4r", version:"11.10.0,REV=2009.07.02.14.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"143725-12", obsoleted_by:"", package:"SUNWntp4u", version:"11.10.0,REV=2009.07.02.14.13") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWntp4S / SUNWntp4r / SUNWntp4u");
}