#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101299);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-8949",
    "CVE-2017-8950",
    "CVE-2017-8951",
    "CVE-2017-8952"
  );
  script_bugtraq_id(99331, 99333);
  script_xref(name:"HP", value:"HPESBGN03763");
  script_xref(name:"HP", value:"emr_na-hpesbgn03763en_us");
  script_xref(name:"CERT", value:"768399");
  script_xref(name:"ZDI", value:"ZDI-12-176");
  script_xref(name:"IAVA", value:"2017-A-0194");

  script_name(english:"HP SiteScope Multiple Vulnerabilities (HPESBGN03763)");
  script_summary(english:"Checks the version of HP SiteScope.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP SiteScope running on the remote host is 11.2x or
11.3x. It is, therefore, affected by multiple vulnerabilities :

  - A cryptographic weakness exists in the ss_pu.jar library
    due to the use of hard-coded encryption keys. A local
    attacker can exploit this to disclose potentially
    sensitive information, such as user credentials in
    configuration files. (CVE-2017-8949)

  - A cryptographic weakness exists in the ss_pu.jar
    library due to the use of risky or broken cryptographic
    algorithms. A local attacker can exploit this to
    disclose potentially sensitive information, such as
    user credentials in configuration files. (CVE-2017-8950)

  - An information disclosure vulnerability exists due to
    credentials stored in Credential Profiles being passed
    in cleartext over HTTP to the client. A local attacker
    can exploit this to disclose sensitive information.
    (CVE-2017-8951)

  - A remote code execution vulnerability exists due to
    improper authentication of users before allowing file
    access when handling SOAP calls to the SiteScope
    service. An unauthenticated, remote attacker can exploit
    this to perform unauthorized actions, such as the
    disclosure of arbitrary files or the execution of
    arbitrary code. (CVE-2017-8952)");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-12-176/");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/768399/");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03763en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4843ab92");
  # https://www.rapid7.com/db/modules/auxiliary/scanner/http/hp_sitescope_getfileinternal_fileaccess
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c83286c6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate update according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8952");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_sitescope_detect.nasl");
  script_require_keys("installed_sw/sitescope", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");


if(report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "sitescope";
# Stops get_http_port from branching
get_install_count(app_name:appname, exit_if_zero:TRUE);

port    = get_http_port(default:8080);
install = get_single_install(app_name:appname,port:port,exit_if_unknown_ver:TRUE);
version = install['version']; # Version level always at least Major.Minor.SP
url     = install['path'   ];
url     = build_url(port:port,qs:url);

if (version =~ "^11\.[23][0-9]" && report_paranoia >= 2)
{
  if (report_verbosity > 0)
  {

    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version); 
