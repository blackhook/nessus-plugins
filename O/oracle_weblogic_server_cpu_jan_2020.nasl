#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132961);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-17359",
    "CVE-2020-2519",
    "CVE-2020-2544",
    "CVE-2020-2546",
    "CVE-2020-2547",
    "CVE-2020-2548",
    "CVE-2020-2549",
    "CVE-2020-2550",
    "CVE-2020-2551",
    "CVE-2020-2552",
    "CVE-2020-6950"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle WebLogic Server Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebLogic Server installed on the remote host is
affected by multiple vulnerabilities:

  - An unspecified vulnerability in the Third Party Tools
    (Bouncy Castle Java Library) component of Oracle WebLogic
    Server. An unauthenticated attacker with network access
    via HTTPS could exploit this vulnerability to compromise
    Oracle WebLogic Server. A successful attack of this
    vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of
    Oracle WebLogic Server. (CVE-2019-1735)

  - An unspecified vulnerability in the Console component of
    Oracle WebLogic Server.  An unauthenticated attacker with
    network access via HTTP could exploit this vulnerability
    to compromise Oracle WebLogic Server. A successful attack
    requires human interaction from a person other than the
    attacker. A successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial denial
    of service (partial DOS) of Oracle WebLogic Server.
    (CVE-2020-2519)
  
  - An unspecified vulnerability in the Console component of
    Oracle WebLogic Server.  An unauthenticated attacker with
    network access via HTTP could exploit this vulnerability
    to compromise Oracle WebLogic Server. A successful attack
    requires human interaction from a person other than the
    attacker. A successful attack of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Oracle WebLogic Server accessible data.
    (CVE-2020-2544)
  
  - An unspecified vulnerability in the Application
    Container - JavaEE component of Oracle WebLogic Server.
    An unauthenticated attacker with network access via T3
    could exploit this vulnerability to compromise Oracle
    WebLogic Server. A successful attack of this vulnerability
    can result in takeover of Oracle WebLogic Server.
    (CVE-2020-2546)
  
  - An unspecified vulnerability in the Console component of
    Oracle WebLogic Server. A high privileged attacker with
    network access via HTTP could exploit this vulnerability
    to compromise Oracle WebLogic Server. A successful attack
    requires human interaction from a person other than the
    attacker and while the vulnerability is in Oracle WebLogic
    Server, attacks may significantly impact additional
    products. Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access to
    some of Oracle WebLogic Server accessible data as well as
    unauthorized read access to a subset of Oracle WebLogic
    Server accessible data. (CVE-2020-2547)
  
  - An unspecified vulnerability in the WLS Core Components 
    of Oracle WebLogic Server. A high privileged attacker
    with network access via HTTP could exploit this
    vulnerability to compromise Oracle WebLogic Server.
    A successful attack requires human interaction from a
    person other than the attacker and while the vulnerability
    is in Oracle WebLogic Server, attacks may significantly
    impact additional products. Successful attacks of this
    vulnerability can result in unauthorized update, insert or
    delete access to some of Oracle WebLogic Server accessible
    data as well as unauthorized read access to a subset of
    Oracle WebLogic Server accessible data.
    (CVE-2020-2548)
  
  - An unspecified vulnerability in the WLS Core Components
    of Oracle WebLogic Server. A high privileged attacker with
    network access via HTTP could exploit this vulnerability to
    compromise Oracle WebLogic Server. A successful attack of this
    vulnerability can result in takeover of Oracle WebLogic Server.
    (CVE-2020-2549)
  
  - An unspecified vulnerability in the WLS Core Components
    of Oracle WebLogic Server. A high privileged attacker with
    logon to the infrastructure where Oracle WebLogic Server
    executes could exploit this vulnerability to compromise 
    racle WebLogic Server. A successful attack of this
    vulnerability can result in unauthorized access to critical
    data or complete access to all Oracle WebLogic Server
    accessible data.
    (CVE-2020-2550)
  
  - An unspecified vulnerability in the WLS Core Components of
    Oracle WebLogic Server. An unauthenticated attacker with
    network access via IIOP could exploit this vulnerability to
    compromise Oracle WebLogic Server. A successful attack of this
    vulnerability can result in takeover of Oracle WebLogic Server.
    (CVE-2020-2551)
  
  - An unspecified vulnerability in the WLS Core Components of
    Oracle WebLogic Server. A high privileged attacker with
    network access via HTTP could exploit this vulnerability
    to compromise Oracle WebLogic Server. A successful attack
    requires human interaction from a person other than the
    attacker and while the vulnerability is in Oracle
    WebLogic Server, attacks may significantly impact
    additional products. A successful attack of this
    vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle WebLogic
    Server accessible data as well as unauthorized read
    access to a subset of Oracle WebLogic Server accessible
    data. (CVE-2020-2552)
  
  - An unspecified vulnerability in the Web Container
    (JavaServer Faces) Components of Oracle WebLogic Server.
    An unauthenticated attacker with network access via
    HTTP could exploit this vulnerability to compromise
    Oracle WebLogic Server. A successful attack of this
    vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle WebLogic
    Server accessible data. (CVE-2020-6950)");
  # https://www.oracle.com/security-alerts/cpujan2020.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?383db271");
  # https://support.oracle.com/rs?type=doc&id=2602410.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bed9f2cb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle
Critical Patch Update advisory.

Refer to Oracle for any additional patch instructions or
mitigation options.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_weblogic_server_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Oracle WebLogic Server");

  exit(0);
}

include('audit.inc');
include('install_func.inc');

app_name = 'Oracle WebLogic Server';

os = get_kb_item_or_exit('Host/OS');
if ('windows' >< tolower(os))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;
}
else port = 0;

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];

fix = NULL;
fix_ver = NULL;

if (version =~ "^12\.2\.1\.4($|[^0-9])")
{
  fix_ver = '12.2.1.4.191220';
  fix = make_list('30689820', '30761841');
}
else if (version =~ "^12\.2\.1\.3($|[^0-9])")
{
  fix_ver = '12.2.1.3.191217';
  fix = make_list('30675853');
}
else if (version =~ "^12\.1\.3\.")
{
  fix_ver = '12.1.3.0.200114';
  fix = make_list('30463093');
}
else if (version =~ "^10\.3\.6\.")
{
  fix_ver = '10.3.6.0.200114';
  fix = make_list('JWEB');
}

if (isnull(fix_ver) || ver_compare(ver:version, fix:fix_ver, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, install['path']);

else
{
  report =
    '\n  Oracle Home    : ' + install['Oracle Home'] +
    '\n  Install path   : ' + install['path'] +
    '\n  Version        : ' + version +
    '\n  Fixes          : ' + join(sep:', ', fix);

  security_report_v4(extra:report, severity:SECURITY_HOLE, port:port);
}
