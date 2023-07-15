#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148976);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-5360", "CVE-2021-2315");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle HTTP Server (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 11.1.1.9.0, 12.2.1.3.0, and 12.2.1.4.0 versions of HTTP Server installed on the remote host are affected by a
vulnerability as referenced in the April 2021 CPU advisory.

  - Vulnerability in the Oracle WebLogic Server Proxy Plug-In product of Oracle Fusion Middleware (component: SSL Module
  (Dell BSAFE Micro Edition Suite)). Supported versions that are affected are 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0.
  Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Oracle
  WebLogic Server Proxy Plug-In. Successful attacks of this vulnerability can result in unauthorized ability to cause
  a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server Proxy Plug-In. (CVE-2020-5360)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Web Listener). Supported
  versions that are affected are 11.1.1.9.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows
  unauthenticated attacker with network access via HTTP to compromise Oracle HTTP Server. Successful attacks require
  human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
  unauthorized update, insert or delete access to some of Oracle HTTP Server accessible data as well as unauthorized
  read access to a subset of Oracle HTTP Server accessible data. (CVE-2021-2315)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();
# 11.1.1.9.0 patch is not released until 31-May-2021
# patches['11.1.1.9.0'] = make_array('fix_ver', '11.1.1.9.????', 'patch', '32797277');
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.210323', 'patch', '32668721');
patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.210324', 'patch', '32673423');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_WARNING
);
