#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(172386);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_name(english:"Solaris 10 (x86) : 151913-21");
  script_summary(english:"Check for patch 151913-21");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing Sun Security Patch number 151913-21"
  );
  script_set_attribute(
    attribute:"description",
    value:
"SunOS 5.10_x86: OpenSSL 1.0.2 patch.
Date this patch was last updated by Sun : Oct/17/22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/151913-21"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 151913-21 or higher");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:151913");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"151913-21", obsoleted_by:"", package:"SUNWopenssl-commands", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"151913-21", obsoleted_by:"", package:"SUNWopenssl-include", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"151913-21", obsoleted_by:"", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"151913-21", obsoleted_by:"", package:"SUNWopensslr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWopenssl-commands / SUNWopenssl-include / SUNWopenssl-libraries / etc");
}
