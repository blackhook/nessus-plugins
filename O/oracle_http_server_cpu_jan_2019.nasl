#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121421);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-2414");
  script_bugtraq_id(106621);

  script_name(english:"Oracle Fusion Middleware Oracle HTTP Server Multiple Vulnerabilities (January 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host is
affected by vulnerabilities as noted in the January 2019 CPU advisory:

  - This vulnerability is in the Oracle HTTP server component of Oracle
    Fusion Middleware (subcomponent: Web Listener). The affected version
    is 12.1.2.3. This is an easily exploitable vulnerability that allows
    a low privileged attacker with logon to the infrastructure where
    Oracle HTTP Server executes to compromise the Oracle HTTP Server.
    Successful attacks of this vulnerability can result in takeover on
    Oracle HTTP Server. (CVE-2019-2414)");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14755ac7");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2019 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2414");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
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
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.180710', 'patch', '28281599');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_WARNING
);
