#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102732);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/31");

  script_xref(name:"IAVB", value:"2017-B-0109-S");

  script_name(english:"F5 Networks BIG-IP Edge Client: session ID vulnerability (K06635145)");
  script_summary(english:"Checks the BIG-IP Edge Client version.");

  script_set_attribute(attribute:"synopsis", value:
"A web client installed on the remote Windows host is affected
by a session id disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Big-IP Edge Client installed on the remote Windows
host is in the range 7071.x through 7132.x. It is, therefore, affected
by a flaw in the BIG-IP Edge Client that exposes the current session
ID as part of the request URI when sending Keep-Alive requests over
an SSL channel. This approach can lead to exploit vulnerabilities in
man-in-the-middle (MITM) SSL terminating proxies, which log the
complete URI in their logs.");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K06635145");
  #https://support.f5.com/kb/en-us/products/big-ip_ltm/releasenotes/related/relnote-supplement-bigip-13-0-0.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d060f053");
  script_set_attribute(attribute:"solution", value:
"Upgrade your Big-IP device to 13.0.0 and ensure that all clients
reinstall their Edge clients from the upgraded device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on in depth analysis of the vendor advisory by Tenable.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_edge_gateway");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("f5_bigip_edge_client_win_detect.nbin");
  script_require_keys("installed_sw/Big-IP Edge Gateway Client for Windows");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");


app = "Big-IP Edge Gateway Client for Windows";

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { "min_version" : "7071", "max_version" : "7132", "fixed_version" : "7136.x" },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

