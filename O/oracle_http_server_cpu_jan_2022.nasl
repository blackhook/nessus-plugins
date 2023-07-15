#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156944);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-40438");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");
  script_xref(name:"IAVA", value:"2022-A-0029");

  script_name(english:"Oracle HTTP Server (Jan 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is affected by a vulnerability as referenced in the
January 2022 CPU advisory:

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: OSSL Module
    (Apache HTTP Server)). Supported versions that are affected are 12.2.1.3.0, 12.2.1.4.0 and 12.2.1.5.0.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle HTTP Server. While the vulnerability is in Oracle HTTP Server, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in takeover of Oracle HTTP
    Server.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40438");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.211130', 'patch', '33619405');
patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.211130', 'patch', '33619347');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_WARNING
);
