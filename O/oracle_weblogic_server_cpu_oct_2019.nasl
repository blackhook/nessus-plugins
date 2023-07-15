#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130012);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2019-2887",
    "CVE-2019-2888",
    "CVE-2019-2889",
    "CVE-2019-2890",
    "CVE-2019-2891",
    "CVE-2019-2907",
    "CVE-2019-11358",
    "CVE-2019-17091"
  );
  script_bugtraq_id(105658, 108023);
  script_xref(name:"IAVA", value:"2019-A-0382");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities:

	-  An unspecified vulnerability in the jquery component of the 
       Web Services of Oracle Weblogic Server.  An unauthenticated, 
       remote attacker can exploit this to gain unauthorized update, 
       insert, or delete access to some of Oracle WebLogic Server 
       accessible data. (CVE-2015-9251) 

	-  An unspecified vulnerability in the Web Services component of 
       Oracle Weblogic Server.  An unauthenticated, remote attacker 
       unauthorized can exploit this to gain read access to some of 
       Oracle WebLogic Server accessible data. (CVE-2019-2887)

    -  An unspecified vulnerability in the Web Services component of 
       Oracle Weblogic Server.  An unauthenticated, remote attacker 
       can exploit this to gain unauthorized read access to some of 
       Oracle WebLogic Server accessible data. (CVE-2019-2888)

    -  An unspecified vulnerability in the Web Services component of 
       Oracle Weblogic Server.  An authenticated, high priviledge 
       remote attacker can exploit this to compromise 
       Oracle WebLogic Server. (CVE-2019-2890)

    -  An unspecified vulnerability in the console component of 
       Oracle Weblogic Server.  An unauthenticated, remote attacker 
       can exploit this to compromise Oracle WebLogic Server. 
       (CVE-2019-2891)

    -  An unspecified vulnerability in the SOAP with Attachments API 
       for Java component of Oracle Weblogic Server.  An 
       unauthenticated, remote attacker can exploit this to gain
       unauthorized update, insert, or delete access to some of 
       Oracle Web Services accessible data as well as unauthorized 
       read access to a subset of Oracle Web Services accessible 
       data. (CVE-2019-2907)
       
    -  An unspecified vulnerability in the ADF Faces jQuery component
       of Oracle Weblogic Server.  An unauthenticated, remote 
       attacker can exploit this to compromise Oracle 
       JDeveloper and ADF resulting in an unauthorized update, 
       insert, or delete access to some of OracleJDeveloper & ADF 
       accessible data as well as unauthorized read access to a 
       subset of Oracle JDeveloper & ADF accessible data. 
       (CVE-2019-11358)

    -  An unspecified vulnerability in the Web Container jQuery 
       component of Oracle Weblogic Server.  An unauthenticated, 
       remote attacker can exploit this to compromise 
       Oracle Service Bus resulting in an unauthorized update, 
       insert, or delete access to some of Service Bus data as well 
       as unauthorized read access to a subset of Oracle Service Bus 
       accessible data. (CVE-2019-11358)

    -  An unspecified vulnerability in the console jQuery component 
       of Oracle Weblogic Server.  An unauthenticated, remote 
       attacker can exploit this to compromise Oracle 
       WebLogic Server resulting in an unauthorized update, insert, 
       or delete access to some of Oracle WebLogic Server data as 
       well as unauthorized read access to a subset of Oracle 
       WebLogic Server accessible data. (CVE-2019-11358)

    -  An unspecified vulnerability in the Web Container Faces jQuery
       component of Oracle Weblogic Server.  An unauthenticated, 
       remote attacker can exploit this to compromise 
       Oracle Service Bus resulting in an unauthorized update, 
       insert, or delete access to some of Oracle WebLogic Server 
       data as well as unauthorized read access to a subset of Oracle
       WebLogic Server accessible data. (CVE-2019-17091)");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b370bc74");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019verbose-5072833.html#FMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d73bb23");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2019 Oracle
Critical Patch Update advisory.

Refer to Oracle for any additional patch instructions or
mitigation options.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2891");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');
include('obj.inc');
include('spad_log_func.inc');

app_name = "Oracle WebLogic Server";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ohome = install["Oracle Home"];
subdir = install["path"];
version = install["version"];

fix = NULL;
fix_ver = NULL;

spad_log(message:"checking version [" + version + "]");
# individual security patches
if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = "12.2.1.3.191015";
  fix = make_list("30386660");
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.191015";
  fix = make_list("30108725");
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.191015";
  fix = make_list("3L3H"); # patchid is obtained from the readme and 10.3.6.x assets are different
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);

spad_log(message:"checking fix [" + obj_rep(fix) + "]");
PATCHED=FALSE;

# Iterate over the list of patches and check the install for the patchID
foreach id (fix)
{
 spad_log(message:"Checking fix id: [" + id +"]");
 if (install[id])
 {
   PATCHED=TRUE;
   break;
 }
}

VULN=FALSE;
if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == -1)
  VULN=TRUE;

if (PATCHED || !VULN)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, subdir);

os = get_kb_item_or_exit("Host/OS");
if ('windows' >< tolower(os))
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}
else port = 0;

report =
  '\n  Oracle Home    : ' + ohome +
  '\n  Install path   : ' + subdir +
  '\n  Version        : ' + version +
  '\n  Fixes          : ' + join(sep:", ", fix);

security_report_v4(extra:report, severity:SECURITY_WARNING, port:port);
