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
  script_id(107450);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-2945", "CVE-2008-3529", "CVE-2008-4225", "CVE-2008-4226", "CVE-2009-0169", "CVE-2009-0170", "CVE-2009-0348", "CVE-2009-2268", "CVE-2009-2712", "CVE-2009-2713", "CVE-2011-0844", "CVE-2011-0847", "CVE-2011-3506");

  script_name(english:"Solaris 10 (sparc) : 126356-06");
  script_summary(english:"Check for patch 126356-06");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 126356-06"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java System Access Manager 7.1 Solaris.
Date this patch was last updated by Sun : Apr/23/11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/126356-06"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 126356-06");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 119, 189, 200, 255, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:126356");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/23");
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

if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamclnt", version:"7.1,REV=06.11.22.00.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamcon", version:"7.1,REV=06.11.22.00.22") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamconsdk", version:"7.1,REV=06.11.22.00.22") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamdistauth", version:"7.1,REV=06.11.22.00.23") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamext", version:"7.1,REV=06.11.20.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamfcd", version:"7.1,REV=06.11.20.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWampwd", version:"7.1,REV=06.11.20.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamrsa", version:"7.1,REV=06.08.30.11.01") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamsam", version:"7.1,REV=06.11.20.12.26") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamsci", version:"7.1,REV=06.11.20.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamsdk", version:"7.1,REV=07.01.18.06.04") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamsdkconfig", version:"7.1,REV=06.12.15.12.35") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamsfodb", version:"7.1,REV=06.11.20.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamsvc", version:"7.1,REV=06.12.19.15.12") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamsvcconfig", version:"7.1,REV=06.11.20.12.28") < 0) flag++;
if (solaris_check_patch(release:"5.10", arch:"sparc", patch:"126356-06", obsoleted_by:"", package:"SUNWamutl", version:"7.1,REV=07.01.18.05.59") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWamclnt / SUNWamcon / SUNWamconsdk / SUNWamdistauth / SUNWamext / etc");
}
