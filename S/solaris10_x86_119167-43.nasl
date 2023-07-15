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
  script_id(107810);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2009-0278", "CVE-2009-2625", "CVE-2011-3559");
  script_xref(name:"IAVT", value:"2009-T-0009-S");

  script_name(english:"Solaris 10 (x86) : 119167-43");
  script_summary(english:"Check for patch 119167-43");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 119167-43"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java System App Server Enterprise Ed 8.1 2005Q1, _x86 Patch32.
Date this patch was last updated by Sun : Oct/18/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/119167-43"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 119167-43");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:119167");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasac", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasacee", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWascml", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWascmn", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWascmnse", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasdem", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasdemdb", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWashdm", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasjdoc", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWaslb", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasman", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasmanee", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasu", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasuee", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWasut", version:"8.1,REV=2004.12.04.00.31") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"119167-43", obsoleted_by:"", package:"SUNWaswbcr", version:"8.1,REV=2004.12.04.00.47") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWasac / SUNWasacee / SUNWascml / SUNWascmn / SUNWascmnse / etc");
}
