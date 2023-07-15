#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159947);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2020-24977",
    "CVE-2021-22901",
    "CVE-2021-39275",
    "CVE-2021-44224"
  );
  script_xref(name:"IAVA", value:"2022-A-0171");

  script_name(english:"Oracle HTTP Server (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle HTTP Server installed on the remote host are affected by multiple vulnerabilities as referenced
in the April 2022 CPU advisory.

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: Web Listener
    (Apache HTTP Server)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle HTTP Server. Successful attacks of this vulnerability can result in takeover of Oracle HTTP Server.
    CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). (CVE-2021-39275)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: SSL Module
    (cURL)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Oracle HTTP
    Server. Successful attacks of this vulnerability can result in takeover of Oracle HTTP Server. CVSS 3.1
    Base Score 8.1 (Confidentiality, Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H). (CVE-2021-22901)

  - Vulnerability in the Oracle HTTP Server product of Oracle Fusion Middleware (component: SSL Module (Apache
    HTTP Server)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Oracle HTTP
    Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of Oracle HTTP Server accessible data and unauthorized ability to cause a partial denial of
    service (partial DOS) of Oracle HTTP Server. CVSS 3.1 Base Score 6.5 (Integrity and Availability impacts).
    CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L). (CVE-2021-44224)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39275");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_http_server_installed.nbin");
  script_require_keys("Oracle/OHS/Installed");

  exit(0);
}

include('oracle_http_server_patch_func.inc');

get_kb_item_or_exit('Oracle/OHS/Installed');
var install_list = get_kb_list_or_exit('Oracle/OHS/*/EffectiveVersion');

var install = branch(install_list, key:TRUE, value:TRUE);

var patches = make_array();
patches['12.2.1.3'] = make_array('fix_ver', '12.2.1.3.220315', 'patch', '33960919');
patches['12.2.1.4'] = make_array('fix_ver', '12.2.1.4.220330', 'patch', '34015729');

oracle_http_server_check_vuln(
  install : install,
  min_patches : patches,
  severity : SECURITY_HOLE
);
