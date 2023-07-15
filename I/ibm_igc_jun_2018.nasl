#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(110416);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2017-1350", "CVE-2018-1432", "CVE-2018-1454");

  script_name(english:"IBM InfoSphere IGC Multiple Vulnerabilities");
  script_summary(english:"Checks the version of IBM InfoSphere IGC");

  script_set_attribute(attribute:"synopsis", value:
"IBM InfoSphere IGC requires a security update");
  script_set_attribute(attribute:"description", value:
"The version of IBM InfoSphere Information Governance Catalog 
installed is less than 11.3.1.2 / 11.7.0.1 or 11.5.x.x and is 
therefore affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22015222");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22014911");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22005503");
  script_set_attribute(attribute:"solution", value:
"Refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:infosphere_information_governance_catalog");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_igc_remote_detect.nbin");
  script_require_keys("installed_sw/IBM IGC");
  script_require_ports(9443, "Services/www");

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:9443);

app_info = vcf::get_app_info(app:"IBM IGC", port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  { "min_version" : "11.3.0.0", "fixed_version" : "11.3.1.2" },
  { "min_version" : "11.7.0.0", "fixed_version" : "11.7.0.1" },
  { "min_version" : "11.5.0.0", "max_version" : "11.5.0.2", "fixed_display" : "Refer to vendor advisory."}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
