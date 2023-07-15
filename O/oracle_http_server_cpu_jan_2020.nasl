#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133146);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-2530", "CVE-2020-2545");

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is affected by the following vulnerabilities as noted in
the January 2020 CPU advisory : 

  - An authentication bypass vulnerability exists in the web listener component. An unauthenticated, remote
    attacker can exploit this via HTTPS to gain unauthorized read, update, insert, delete access to a subset
    of Oracle HTTP Server accessible data. (CVE-2020-2530)

  - A Denial of Service (DoS) vulnerability exists in the SSL API component of the Oracle Security Service. An
    unauthenticated, remote attacker can exploit this via HTTPS to cause a partial DoS. (CVE-2020-2545)");
  # https://www.oracle.com/security-alerts/cpujan2020.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?383db271");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2020 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2530");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");

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
patches['11.1.1.9'] = make_array('fix_ver', '11.1.1.9.200114', 'patch', '30654519');
patches['12.1.3.0'] = make_array('fix_ver', '12.1.3.0.200114', 'patch', '30748483');
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.191219', 'patch', '30687404');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_WARNING
);
