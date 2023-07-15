#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86569);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2003-1418",
    "CVE-2014-0191",
    "CVE-2015-1829",
    "CVE-2015-2808",
    "CVE-2015-4812",
    "CVE-2015-4914",
    "CVE-2016-2183"
  );
  script_bugtraq_id(
    67233,
    73684,
    75164,
    77195,
    77201,
    92630
  );

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (October 2015 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by multiple vulnerabilities :

  - (CVE-2003-1418)

  - A denial of service vulnerability exists in libxml2,
    related to the xmlParserHandlePEReference() function in
    file parser.c, due to loading external parameter
    entities without regard to entity substitution or
    validation being enabled, as in the case of entity
    substitution in the doctype prolog. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    XML content, to exhaust the system CPU, memory, or file
    descriptor resources. (CVE-2014-0191)

  - An unspecified vulnerability exists in the Web Listener
    component that allows an unauthenticated, remote
    attacker to impact availability. (CVE-2015-1829)

  -  (CVE-2015-2808)

  - An unspecified vulnerability exists in the OSSL Module
    that allows an unauthenticated, remote attacker to
    impact confidentiality. (CVE-2015-4812)

  - An unspecified vulnerability exists in the Web Listener
    component that allows an authenticated, remote attacker
    to impact confidentiality. (CVE-2015-4914)

  - (CVE-2016-2183)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2015 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

install = branch(install_list, key:TRUE, value:TRUE);

patches = make_array();
patches['10.1.3.5'] = make_array('fix_ver', '10.1.3.5.151020', 'patch', '21845960');
patches['11.1.1.7'] = make_array('fix_ver', '11.1.1.7.151020', 'patch', '21640624');
patches['11.1.1.9'] = make_array('fix_ver', '11.1.1.9.151020', 'patch', '21663064');
patches['12.1.2.0'] = make_array('fix_ver', '12.1.2.0.151120', 'patch', '21768251');
patches['12.1.3.0'] = make_array('fix_ver', '12.1.3.0.160130', 'patch', '21640673');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_WARNING
);
