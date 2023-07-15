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
  script_id(108101);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-10062");

  script_name(english:"Solaris 10 (x86) : 147674-11");
  script_summary(english:"Check for patch 147674-11");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 147674-11"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Solaris component of Oracle Sun Systems Products
Suite (subcomponent: Oracle Java Web Console). The supported version
that is affected is 10. Easily exploitable vulnerability allows low
privileged attacker with logon to the infrastructure where Solaris
executes to compromise Solaris. Successful attacks of this
vulnerability can result in unauthorized update, insert or delete
access to some of Solaris accessible data as well as unauthorized read
access to a subset of Solaris accessible data and unauthorized ability
to cause a partial denial of service (partial DOS) of Solaris."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/147674-11"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 147674-11 or higher");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10062");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:125953");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:147674");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
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
if (package_arch != "i386") audit(AUDIT_ARCH_NOT, "i386", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmcon", version:"3.0.2,REV=2006.12.08.20.48") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmconr", version:"3.0.2,REV=2006.12.08.23.39") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmcos", version:"3.0.2,REV=2006.12.08.23.39") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmcosx", version:"3.0.2,REV=2006.12.08.23.39") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"147674-11", obsoleted_by:"", package:"SUNWmctag", version:"3.0.2,REV=2006.12.08.20.48") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWmcon / SUNWmconr / SUNWmcos / SUNWmcosx / SUNWmctag");
}
