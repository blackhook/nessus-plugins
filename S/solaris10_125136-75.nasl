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
  script_id(107416);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-0217", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-3403");

  script_name(english:"Solaris 10 (sparc) : 125136-75");
  script_summary(english:"Check for patch 125136-75");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 125136-75"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"JavaSE 6: update 75 patch (equivalent to JDK 6u75).
Date this patch was last updated by Sun : Apr/14/14"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/125136-75"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 125136-75 or higher");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2675");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:125136");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125136-75", obsoleted_by:"152919-01 152076-05 ", package:"SUNWj6cfg", version:"1.6.0,REV=2006.11.29.05.57") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125136-75", obsoleted_by:"152919-01 152076-05 ", package:"SUNWj6dev", version:"1.6.0,REV=2006.11.29.05.57") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125136-75", obsoleted_by:"152919-01 152076-05 ", package:"SUNWj6dmo", version:"1.6.0,REV=2006.11.29.05.57") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125136-75", obsoleted_by:"152919-01 152076-05 ", package:"SUNWj6jmp", version:"1.6.0,REV=2006.12.07.19.24") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125136-75", obsoleted_by:"152919-01 152076-05 ", package:"SUNWj6man", version:"1.6.0,REV=2006.12.07.16.37") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"125136-75", obsoleted_by:"152919-01 152076-05 ", package:"SUNWj6rt", version:"1.6.0,REV=2006.11.29.05.57") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWj6cfg / SUNWj6dev / SUNWj6dmo / SUNWj6jmp / SUNWj6man / etc");
}
