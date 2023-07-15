#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173033);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2022-2068",
    "CVE-2022-26377",
    "CVE-2022-28330",
    "CVE-2022-28615",
    "CVE-2022-30522",
    "CVE-2022-30556",
    "CVE-2022-31813",
    "CVE-2022-47986",
    "CVE-2023-22868"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/14");

  script_name(english:"IBM Aspera Faspex < 4.4.2 Patch Level 2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A file transfer application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of IBM Aspera Faspex running on the remote web server is prior to
4.4.2 Patch Level 2. It is, therefore, affected by multiple vulnerabilities, including:

    - IBM Aspera Faspex 4.4.2 Patch Level 1 and earlier could allow a remote attacker to execute arbitrary code on the
      system, caused by a YAML deserialization flaw. By sending a specially crafted obsolete API call, an attacker could
      exploit this vulnerability to execute arbitrary code on the system. (CVE-2022-47986)

    - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many distant
      matches. (CVE-2018-25032)

    - Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of Apache
      HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. (CVE-2022-26377)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6952319");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Aspera Faspex version 4.4.2 Patch Level 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2068");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-47986");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:aspera_faspex");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_aspera_faspex_web_detect.nbin");
  script_require_keys("installed_sw/IBM Aspera Faspex");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'IBM Aspera Faspex', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version':'4.4.2.185316', 'fixed_display':'4.4.2.185316 (4.4.2 Patch Level 2)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);