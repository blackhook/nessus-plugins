#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92542);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2003-1418",
    "CVE-2015-2808",
    "CVE-2016-2183",
    "CVE-2016-3482"
  );
  script_bugtraq_id(73684, 92026, 92630);

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (July 2016 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by multiple vulnerabilities as noted in the July 2016
CPU advisory.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d87d8f4a");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3482");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

install = branch(install_list, key:TRUE, value:TRUE);

patches = make_array();
patches['11.1.1.9'] = make_array('fix_ver', '11.1.1.9.160719', 'patch', '23623015');
patches['12.1.3.0'] = make_array('fix_ver', '12.1.3.0.160707', 'patch', '22557350');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_WARNING
);
