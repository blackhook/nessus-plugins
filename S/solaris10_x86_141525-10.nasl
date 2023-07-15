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
  script_id(108025);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3555", "CVE-2009-4075");

  script_name(english:"Solaris 10 (x86) : 141525-10");
  script_summary(english:"Check for patch 141525-10");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote host is missing Sun Security Patch number 141525-10"
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SunOS 5.10_x86: ssh and openssl patch.
Date this patch was last updated by Sun : Jun/18/10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/141525-10"
  );
  script_set_attribute(attribute:"solution", value:"Install patch 141525-10");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:128254");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:128319");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:138863");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:139501");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140119");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140412");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140591");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:140775");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:141525");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:141919");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:142048");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:10:142243");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/18");
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

if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWckr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWcry", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWcryr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWcsl", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWhea", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWopenssl-commands", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWopenssl-include", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWopenssl-libraries", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWsshcu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWsshdr", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWsshdu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;
if (solaris_check_patch(release:"5.10_x86", arch:"i386", patch:"141525-10", obsoleted_by:"142910-17 ", package:"SUNWsshu", version:"11.10.0,REV=2005.01.21.16.34") < 0) flag++;

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
  audit(AUDIT_PACKAGE_NOT_INSTALLED, "SUNWckr / SUNWcry / SUNWcryr / SUNWcsl / SUNWhea / etc");
}
