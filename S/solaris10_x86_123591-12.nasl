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
  script_id(107893);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2138", "CVE-2009-0922", "CVE-2009-3229", "CVE-2009-3230");

  script_name(english:"Solaris 10 (x86) : 123591-12");
  script_summary(english:"Check for patch 123591-12");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 123591-12"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: PostgreSQL patch.
Date this patch was last updated by Sun : Jan/14/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/123591-12"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 123591-12");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:123591");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/14");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-contrib", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-devel", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-docs", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-jdbc", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-jdbcS", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-libs", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-pl", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-server-data", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-server", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-tcl", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr-tclS", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgr", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"123591-12", obsoleted_by:"", package:"SUNWpostgrS", version:"11.10.0,REV=2006.03.22.03.03") < 0) flag++;

if (flag) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : solaris_get_report()
  );
} else {
  patch_fix = solaris_patch_fix_get();
  if (!empty_or_null(patch_fix)) audit(AUDIT_PATCH_INSTALLED, patch_fix, "Solaris 10");
  tested = solaris_pkg_tests_get();
  if (!empty_or_null(tested)) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWpostgr / SUNWpostgr-contrib / SUNWpostgr-devel / etc");
}
