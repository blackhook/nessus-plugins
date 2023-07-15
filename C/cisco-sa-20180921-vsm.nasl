#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122249);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-15427");
  script_bugtraq_id(105381);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180921-vsm");
  script_xref(name:"IAVA", value:"2019-A-0057");

  script_name(english:"Cisco Video Surveillance Manager Appliance Default Password Vulnerability(cisco-sa-20180921-vsm)");
  script_summary(english:"Checks VSM version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a default password vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco Video
Surveillance Manager installed on the remote host is affected by
a default password vulnerability. An attacker could exploit this
vulnerability to login as the 'root' user and execute arbitrary
commands.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180921-vsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fc73780");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Video Surveillance Manager 7.12 or later. 
Alternatively customers who do not want to upgrade to 7.12
should contact Cisco TAC for further assistance");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15427");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:video_surveillance_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vsm_detect.nasl");
  script_require_keys("installed_sw/Cisco Video Surveillance Management Console");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:80);
app = "Cisco Video Surveillance Management Console";

app_info = vcf::get_app_info(app:app, port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);
fix = "7.12 or later. Alternatively contact Cisco TAC for further assistance";

# Cisco notes that 7.10 and 7.11 are Vuln: Vulnerable, contact the Cisco TAC
# 7.12 is noted as not affected.

constraints = [
  { "min_version" : "7.10", "fixed_version" : "7.12", "fixed_display" : fix },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

