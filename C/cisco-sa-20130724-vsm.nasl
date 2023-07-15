#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69856);
  script_version("1.7");
  script_cvs_date("Date: 2019/03/27 13:17:50");

  script_cve_id("CVE-2013-3429", "CVE-2013-3430", "CVE-2013-3431");
  script_bugtraq_id(61430, 61431, 61432);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130724-vsm");

  script_name(english:"Cisco Video Surveillance Manager Multiple Vulnerabilities (cisco-sa-20130724-vsm)");
  script_summary(english:"Checks VSM version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Cisco Video
Surveillance Manager installed on the remote host is affected by
multiple vulnerabilities :

  - The application is affected by a directory traversal
    vulnerability because Cisco VSM does not properly
    validate user-supplied input to the
    'monitor/logselect.php' and 'read_log.jsp' scripts.
    This can allow a remote, unauthorized attacker to gain
    access to arbitrary files on the remote host by sending
    a specially crafted request. (CVE-2013-3429)

  - The application allows access to sensitive data without
    requiring authentication.  Data such as configuration,
    monitoring pages archives, and system logs can be
    accessed by attackers without requiring authentication.
    (CVE-2013-3430, CVE-2013-3431)"
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130724-vsm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?face9c20");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Video Surveillance Manager 7.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3430");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:video_surveillance_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vsm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Cisco Video Surveillance Management Console");

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:80);
app = "Cisco Video Surveillance Management Console";

app_info = vcf::get_app_info(app:app, port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "fixed_version" : "7.0.0" },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
