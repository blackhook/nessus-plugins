#
# (C) Tenable Network Security, Inc.
#
# The descriptive text in this plugin was
# extracted from the Oracle SunOS Patch Updates.
#
include("compat.inc");

if (description)
{
  script_id(124079);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/23");

  script_cve_id("CVE-2018-20685");

  script_name(english:"Solaris 10 (x86) : 148105-29");
  script_summary(english:"Check for patch 148105-29");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 148105-29"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Oracle Solaris component of Oracle Sun Systems
Products Suite (subcomponent: SunSSH). The supported version that is
affected is 10. Difficult to exploit vulnerability allows
unauthenticated attacker with network access via SSH to compromise
Oracle Solaris. Successful attacks require human interaction from a
person other than the attacker. Successful attacks of this
vulnerability can result in unauthorized creation, deletion or
modification access to critical data or all Oracle Solaris accessible
data."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/148105-29"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 148105-29 or higher");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20685");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148097");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:148105");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
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
if (package_arch != "i386") audit(AUDIT_ARCH_NOT, "i386", package_arch);
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148105-29", obsoleted_by:"", package:"SUNWesu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148105-29", obsoleted_by:"", package:"SUNWsshcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148105-29", obsoleted_by:"", package:"SUNWsshdr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148105-29", obsoleted_by:"", package:"SUNWsshdu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"148105-29", obsoleted_by:"", package:"SUNWsshu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

if (flag) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : solaris_get_report()
  );
} else {
  patch_fix = solaris_patch_fix_get();
  if (!empty_or_null(patch_fix)) audit(AUDIT_PATCH_INSTALLED, patch_fix, "Solaris 10");
  tested = solaris_pkg_tests_get();
  if (!empty_or_null(tested)) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWesu / SUNWsshcu / SUNWsshdr / SUNWsshdu / SUNWsshu");
}
