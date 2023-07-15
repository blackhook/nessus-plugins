#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100380);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2016-2183", "CVE-2017-1092", "CVE-2017-1310");
  script_bugtraq_id(92630, 98615, 99309);
  script_xref(name:"IAVA", value:"2017-A-0218-S");

  script_name(english:"IBM Informix Dynamic Server 11.50.xCn < 11.50.xC9 / 11.70.xCn < 11.70.xC9 / 12.10.xCn < 12.10.xC8W2 Multiple Vulnerabilities (SWEET32)");
  script_summary(english:"Checks version of Informix Server.");

  script_set_attribute(attribute:"synopsis", value:
"A database server installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Informix Dynamic Server installed on the remote
host is 11.50.xCn prior to 11.50.xC9, 11.70.xCn prior to 11.70.xC9, or
12.10.xCn prior to 12.10.xC8W2. It is, therefore, affected by a
multiple vulnerabilities :

  - A vulnerability, known as SWEET32, exists in the OpenSSL
    component in the 3DES and Blowfish algorithms due to the
    use of weak 64-bit block ciphers by default. A
    man-in-the-middle attacker who has sufficient resources
    can exploit this vulnerability, via a 'birthday' attack,
    to detect a collision that leaks the XOR between the
    fixed secret and a known plaintext, allowing the
    disclosure of the secret text, such as secure HTTPS
    cookies, and possibly resulting in the hijacking of an
    authenticated session. (CVE-2016-2183)

  - A remote code execution vulnerability exists in the Open
    Admin Tool that allows an unauthenticated, remote
    attacker to execute arbitrary code with administrator
    privileges. (CVE-2017-1092)

  - A denial of service vulnerability exists due to an
    overflow condition in the FORMAT_UNITS() function caused
    by improper validation of user-supplied input. An
    authenticated, remote attacker can exploit this to write
    large assertion failure files to the server, resulting
    in a crash of the server. Note that this vulnerability
    only affects the 12.10 version branch. (CVE-2017-1310)");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22002897");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22004930");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Informix Dynamic Server version 11.50.xC9 / 11.70.xC9 /
12.10.xC8W2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1092");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM OpenAdmin Tool SOAP welcomeServer PHP Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix_dynamic_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_informix_server_installed.nasl");
  script_require_keys("installed_sw/IBM Informix Dynamic Server");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include("install_func.inc");
include('misc_func.inc');

ids_app = 'IBM Informix Dynamic Server';
ids_install = get_single_install(app_name:ids_app, exit_if_unknown_ver:TRUE);

ids_ver   = ids_install['version'];
ids_path  = ids_install['path'];

ids_fix   = NULL;

item = pregmatch(pattern: "[cC]([0-9]+)(?:[wW]([0-9]+))?(?:[^0-9]|$)", string: ids_ver);
if(isnull(item) || isnull(item[1])) audit(AUDIT_VER_FORMAT, ids_ver);

w_num = 0;
c_num = int(item[1]);
if (!isnull(item) && !isnull(item[2])) w_num = int(item[2]);

# 11.50 < 11.50.xC9
if (ids_ver =~ "^11\.50($|[^0-9])" && c_num < 9) 
  ids_fix = "11.50.xC9";
# 11.70 < 11.70.xC9
else if (ids_ver =~ "^11\.70($|[^0-9])" && c_num < 9)
  ids_fix = "11.70.xC9";
# 12.10 < 12.10.xC8W2
else if (ids_ver =~ "^12\.10($|[^0-9])" && (c_num < 8 || ( c_num == 8 && w_num < 2 )))
  ids_fix = "12.10.xC8W2";
else
  audit(AUDIT_INST_PATH_NOT_VULN, ids_app, ids_ver, ids_path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

report =
  '\n' + 'The install of ' + ids_app + ' is vulnerable :' +
  '\n' +
  '\n' + '  Path              : ' + ids_path +
  '\n' + '  Installed version : ' + ids_ver  +
  '\n' + '  Fixed version     : ' + ids_fix  +
  '\n';

  server_instances = get_kb_item("Host/" + ids_app + "/Server Instances");
  if (!empty_or_null(server_instances))
  {
    instance_list = split(server_instances, sep:' / ', keep:FALSE);
    report += '  Server instances  : ' + '\n      - ' + join(instance_list, sep:'\n      - ') + '\n';
  }

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
