#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154340);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-20843",
    "CVE-2020-1971",
    "CVE-2021-2480",
    "CVE-2021-35666"
  );
  script_xref(name:"IAVA", value:"2021-A-0480");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle HTTP Server (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 11.1.1.9.0, 12.2.1.3.0, and 12.2.1.4.0 versions of HTTP Server installed on the remote host are affected by multiple
vulnerabilities as referenced in the October 2021 CPU advisory.

  - Vulnerability in the Oracle WebLogic Server Proxy Plug-In product of Oracle Fusion Middleware (component:
    SSL Module (LibExpat)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle WebLogic Server Proxy Plug-In. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle WebLogic Server Proxy
    Plug-In. CVSS 3.1 Base Score 7.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2018-20843)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: OSSL Module). The
    supported version that is affected is 11.1.1.9.0. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via HTTPS to compromise Oracle HTTP Server. Successful
    attacks of this vulnerability can result in unauthorized access to critical data or complete access to all
    Oracle HTTP Server accessible data. CVSS 3.1 Base Score 5.9 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N). (CVE-2021-35666)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: SSL Module
    (OpenSSL)). The supported version that is affected is 12.2.1.4.0. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via HTTPS to compromise Oracle HTTP Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of Oracle HTTP Server. CVSS 3.1 Base Score 5.9 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2020-1971)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35666");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
patches['11.1.1.9'] = make_array('fix_ver', '11.1.1.9.210826', 'patch', '33311587');
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.210826', 'patch', '33283753');
patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.210826', 'patch', '33283762');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
