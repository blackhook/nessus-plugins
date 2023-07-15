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
  script_id(107461);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"Solaris 10 (sparc) : 127683-07");
  script_summary(english:"Check for patch 127683-07");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 127683-07"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Management Center 4.0: Patch for Solar.
Date this patch was last updated by Sun : Nov/25/09"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/127683-07"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 127683-07");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:127683");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/25");
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
if (package_arch != "sparc") audit(AUDIT_ARCH_NOT, "sparc", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesae", version:"4.0,REV=2.10.2007.10.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesagt", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesamn", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesbui", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWescli", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesclt", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWescom", version:"4.0,REV=2.10.2007.10.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWescon", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesdb", version:"4.0,REV=2.10.2007.10.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesjp", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesken", version:"4.0,REV=2.10.2007.10.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWessa", version:"4.0,REV=2.10.2007.10.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWessrv", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWessvc", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWesweb", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"127683-07", obsoleted_by:"143323-02 ", package:"SUNWsusrv", version:"4.0,REV=2.8.2007.11.16") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWesae / SUNWesagt / SUNWesamn / SUNWesbui / SUNWescli / etc");
}
