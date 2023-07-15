#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118205);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2018-2902",
    "CVE-2018-3191",
    "CVE-2018-3197",
    "CVE-2018-3201",
    "CVE-2018-3213",
    "CVE-2018-3245",
    "CVE-2018-3246",
    "CVE-2018-3248",
    "CVE-2018-3249",
    "CVE-2018-3250",
    "CVE-2018-3252"
  );
  script_bugtraq_id(
    105606,
    105611,
    105613,
    105628,
    105654
  );

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (October 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities:

  - Vulnerabilities in the Oracle WebLogic Server component of Oracle 
    Fusion Middleware (subcomponent: WLS Core Components). Easily 
    exploitable vulnerabilities allow unauthenticated attacker 
    with network access via T3 to compromise Oracle WebLogic Server. 
    Successful attacks of this vulnerabilities can result in takeover 
    of Oracle WebLogic Server. Supported versions that are affected:
     - 10.3.6.0: CVE-2018-3191, CVE-2018-3245, CVE-2018-3252
     - 12.1.3.0: CVE-2018-3191, CVE-2018-3197, CVE-2018-3245, CVE-2018-3252
     - 12.2.1.3: CVE-2018-3191, CVE-2018-3201, CVE-2018-3245, CVE-2018-3252

  - Vulnerabilities in the Oracle WebLogic Server component of Oracle 
    Fusion Middleware (subcomponent: WLS - Web Services). Easily
    exploitable vulnerabilities allow unauthenticated attacker with
    network access via HTTP to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerabilities can result in
    unauthorized access to critical data. Supported versions that
    are affected:
     - 10.3.6.0: CVE-2018-3248, CVE-2018-3249, CVE-2018-3250
     - 12.1.3.0: CVE-2018-3246
     - 12.2.1.3: CVE-2018-3246

  - Vulnerability in the Oracle WebLogic Server component of Oracle
    Fusion Middleware (subcomponent: Docker Images). The supported
    version that is affected is prior to Docker 12.2.1.3.20180913.
    Easily exploitable vulnerability allows unauthenticated attacker
    with network access via T3 to compromise Oracle WebLogic Server.
    Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all
    Oracle WebLogic Server accessible data. (CVE-2018-3213)

  - Vulnerability in the Oracle WebLogic Server component of Oracle
    Fusion Middleware (subcomponent: Console). Supported versions
    that are affected are 10.3.6.0 and 12.1.3.0. Easily exploitable
    vulnerability allows low privileged attacker with network access
    via HTTP to compromise Oracle WebLogic Server. Successful attacks
    of this vulnerability can result in unauthorized read access to
    a subset of Oracle WebLogic Server accessible data.
    (CVE-2018-2902)");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2018-4428296.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?705136d8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2018 Oracle
Critical Patch Update advisory.

Refer to Oracle for any additional patch instructions or
mitigation options.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3191");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("obj.inc");
include("spad_log_func.inc");

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
  fix_ver = "12.2.1.3.181016";
  fix = make_list("28298734");
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = "12.1.3.0.181016";
  fix = make_list("28298916");
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = "10.3.6.0.181016";
  fix = make_list("GENM"); # patchid is obtained from the readme and 10.3.6.x assets are different
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

security_report_v4(extra:report, severity:SECURITY_HOLE, port:port);
