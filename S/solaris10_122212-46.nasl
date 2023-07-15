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
  script_id(107378);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-3404");

  script_name(english:"Solaris 10 (sparc) : 122212-46");
  script_summary(english:"Check for patch 122212-46");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 122212-46"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNOME 2.6.0: GNOME Desktop Patch.
Date this patch was last updated by Sun : Nov/10/12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/122212-46"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 122212-46 or higher");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3404");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:119366");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:119370");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:119412");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:119542");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:119892");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:119908");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:120133");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:120135");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:120296");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:122212");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:143510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:146576");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:147988");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:149106");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/10");
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
if (package_arch != "sparc") audit(AUDIT_ARCH_NOT, "sparc", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWPython", version:"2.3.3,REV=10.0.3.2004.12.15.14.07") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-desktop-prefs-share", version:"2.6.0,REV=10.0.3.2004.12.21.13.18") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-desktop-prefs", version:"2.6.0,REV=10.0.3.2004.12.21.13.18") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-display-mgr-root", version:"2.6.0,REV=10.0.3.2004.12.15.21.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-display-mgr-share", version:"2.6.0,REV=10.0.3.2004.12.15.21.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-display-mgr", version:"2.6.0,REV=10.0.3.2004.12.15.21.16") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-file-mgr-root", version:"2.6.0,REV=10.0.3.2004.12.15.19.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-file-mgr-share", version:"2.6.0,REV=10.0.3.2004.12.15.19.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-file-mgr", version:"2.6.0,REV=10.0.3.2004.12.15.19.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-img-editor-share", version:"2.6.0,REV=10.0.3.2004.12.16.17.35") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-img-editor", version:"2.6.0,REV=10.0.3.2004.12.16.17.35") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-img-viewer-share", version:"2.6.0,REV=10.0.3.2004.12.15.23.40") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-libs-devel", version:"2.6.0,REV=10.0.3.2004.12.15.17.32") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-libs-root", version:"2.6.0,REV=10.0.3.2004.12.15.17.32") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-libs-share", version:"2.6.0,REV=10.0.3.2004.12.15.17.32") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-libs", version:"2.6.0,REV=10.0.3.2004.12.15.17.32") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-panel-devel", version:"2.6.0,REV=10.0.3.2004.12.15.19.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-panel-root", version:"2.6.0,REV=10.0.3.2004.12.15.19.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-panel-share", version:"2.6.0,REV=10.0.3.2004.12.15.19.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-panel", version:"2.6.0,REV=10.0.3.2004.12.15.19.13") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-session-share", version:"2.6.0,REV=10.0.3.2004.12.21.13.03") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-session", version:"2.6.0,REV=10.0.3.2004.12.21.13.03") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"122212-46", obsoleted_by:"", package:"SUNWgnome-themes-share", version:"2.6.0,REV=10.0.3.2004.12.15.17.42") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWPython / SUNWgnome-desktop-prefs / etc");
}
