#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124156);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-3822");
  script_bugtraq_id(106950);
  script_xref(name:"IAVA", value:"2019-A-0128");
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server (Apr 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a stack-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is affected by a stack-based buffer overflow as noted in
the April 2019 CPU advisory. The condition exists in the included cURL library due to using unsigned math when
preventing the overflow. An unauthenticated, remote attacker can exploit this, via a specially crafted HTTP request, to
cause a denial of service condition or the execution of arbitrary code.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06438612");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2019 Oracle
  Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

install = branch(install_list, key:TRUE, value:TRUE);

patches = make_array();
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.190310', 'patch', '29407043');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
