#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(142212);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-5482", "CVE-2019-10097", "CVE-2020-1967");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is affected by the following vulnerabilities as
referenced in the October 2020 CPU advisory:

  - A denial of service (DoS) vulnerability exists in the SSL Module (OpenSSL). An unauthenticated, remote
    attacker with network access via HTTPS, can exploit this issue to cause a hang or frequently repeatable 
    crash (complete DoS) of Oracle HTTP Server. (CVE-2020-1967)

  - An unspecified vulnerability exists in the Apache HTTP Server Core component.  A authenticated, remote
    attacker with network access via HTTP, can exploit this issue to compromise the Oracle HTTP Server. 
    Successful attacks of this vulnerability can result in takeover of Oracle HTTP Server. (CVE-2019-10097)

  - An unspecified vulnerability exists in Web Listener (cURL). An unauthenticated, remote attacker with
    network access via TFTP can exploit this issue to compromise Oracle HTTP Server. Successful attacks of
    this vulnerability can result in takeover of Oracle HTTP Server. (CVE-2019-5482)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5482");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

install = branch(install_list, key:TRUE, value:TRUE);

patches = make_array();
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.200911', 'patch', '31876370');
patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.200826', 'patch', '31808404');

oracle_http_server_check_vuln(install : install, min_patches : patches, severity : SECURITY_HOLE);
