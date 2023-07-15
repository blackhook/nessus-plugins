#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106299);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2015-7501",
    "CVE-2015-7940",
    "CVE-2016-0635",
    "CVE-2016-1182",
    "CVE-2016-2107",
    "CVE-2016-2179",
    "CVE-2017-3732",
    "CVE-2017-5461",
    "CVE-2017-5645",
    "CVE-2017-9798",
    "CVE-2017-10068",
    "CVE-2017-10262",
    "CVE-2017-10273",
    "CVE-2017-10352",
    "CVE-2017-12617",
    "CVE-2018-2561",
    "CVE-2018-2564",
    "CVE-2018-2584",
    "CVE-2018-2596",
    "CVE-2018-2601",
    "CVE-2018-2625",
    "CVE-2018-2711",
    "CVE-2018-2713",
    "CVE-2018-2715",
    "CVE-2018-2760"
  );
  script_bugtraq_id(
    78215,
    79091,
    89760,
    91067,
    91869,
    92987,
    95814,
    97702,
    98050,
    100872,
    100954,
    102442,
    102535,
    102539,
    102541,
    102545,
    102550,
    102553,
    102558,
    102562,
    102565,
    102567,
    102569,
    102573,
    103826
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by multiple vulnerabilities as noted in the January 2018
CPU advisory.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6072c657");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2018-3678067.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76507bf8");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2018 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7501");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-10352");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

install = branch(install_list, key:TRUE, value:TRUE);

patches = make_array();
patches['11.1.1.7'] = make_array('fix_ver', '11.1.1.7.180116', 'patch', '27197885');
patches['11.1.1.9'] = make_array('fix_ver', '11.1.1.9.180116', 'patch', '27301611');
patches['12.1.3.0'] = make_array('fix_ver', '12.1.3.0.190130', 'patch', '27244723');
patches['12.2.1.2'] = make_array('fix_ver', '12.2.1.2.171220', 'patch', '27198002');
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.171117', 'patch', '27149535');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
