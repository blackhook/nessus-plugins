#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112115);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-15694",
    "CVE-2018-15695",
    "CVE-2018-15696",
    "CVE-2018-15697",
    "CVE-2018-15698",
    "CVE-2018-15699"
  );
  script_xref(name:"TRA", value:"TRA-2018-22");

  script_name(english:"ASUSTOR Data Master < 3.1.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ASUSTOR Data Master.");

  script_set_attribute(attribute:"synopsis", value:
"A web interface for ASUSTOR NAS devices running on the remote web
server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the ASUSTOR Data
Master (ADM) web interface running on the remote web server is prior
to 3.1.6. It is, therefore, affected by multiple vulnerabilities:

  - CVE-2018-15694: Authenticated File Upload

  - CVE-2018-15695: Authenticated Arbitrary File Deletion

  - CVE-2018-15696: Authenticated Account Enumeration

  - CVE-2018-15697: Authenticated File Disclosure

  - CVE-2018-15698: Authenticated File Disclosure

  - CVE-2018-15699: MITM XSS");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-22");
  # http://download.asustor.com/download/docs/releasenotes/RN_ADM_3.1.6.RKE1.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f7da7ef");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ASUSTOR Data Master (ADM) version 3.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:asustor:data_master");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("asustor_data_master_detect.nbin");
  script_require_keys("installed_sw/ASUSTOR Data Master");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "ASUSTOR Data Master";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [{ "fixed_version" : "3.1.6" }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
