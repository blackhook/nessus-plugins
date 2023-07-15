#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106349);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2015-7501",
    "CVE-2015-7940",
    "CVE-2016-0635",
    "CVE-2016-1182",
    "CVE-2016-2107",
    "CVE-2016-2179",
    "CVE-2017-3732",
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
    "CVE-2018-2594",
    "CVE-2018-2595",
    "CVE-2018-2596",
    "CVE-2018-2601",
    "CVE-2018-2610",
    "CVE-2018-2625",
    "CVE-2018-2711",
    "CVE-2018-2713",
    "CVE-2018-2715",
    "CVE-2018-2733"
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
    102634,
    102637,
    102641,
    102643
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Oracle iPlanet Web Server 7.0.x < 7.0.27 NSS Unspecified Vulnerability (January 2018 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Server
(formerly known as Sun Java System Web Server) running on the remote
host is 7.0.x prior to 7.0.27 Patch 26834070. It is, therefore,
affected by an unspecified vulnerability in the Network Security
Services (NSS) library with unknown impact.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae82f1b1");
  # https://support.oracle.com/epmos/faces/SearchDocDisplay?_adf.ctrl-state=14v5w3zyq8_4&_afrLoop=466151680153736#babhdcfj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fccabced");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Server version 7.0.27 or later as
referenced in the January 2018 Oracle Critical Patch Update advisory.");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:network_security_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_iplanet_web_server_detect.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Server");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app_name = "Oracle iPlanet Web Server";
port = get_http_port(default:8989);

install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];

fix = "7.0.27";
min = "7.0";



# Affected 7.0.x < 7.0.27
if (
  ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
