#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(130508);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/07");

  script_cve_id("CVE-2005-2495", "CVE-2005-3099", "CVE-2006-3467", "CVE-2006-3739", "CVE-2007-1667", "CVE-2007-4070", "CVE-2008-5684");

  script_name(english:"Solaris 10 (sparc) : 119059-74");
  script_summary(english:"Check for patch 119059-74");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119059-74"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"X11 6.6.2: Xsun patch.
Date this patch was last updated by Sun : Nov/04/19"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119059-74"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 119059-74 or higher");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1667");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:119059");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:121868");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/05");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwacx", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwfnt", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwfs", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwice", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwinc", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwman", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwopt", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwplr", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwplt", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwpmn", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwrtl", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwsrv", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"119059-74", obsoleted_by:"", package:"SUNWxwxst", version:"6.6.2.7400,REV=0.2004.12.15") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWxwacx / SUNWxwfnt / SUNWxwfs / SUNWxwice / SUNWxwinc / etc");
}
