#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128177);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1679");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn33987");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190206-rest-api-ssrf");

  script_name(english:"Cisco TelePresence VCS / Expressway Series < 12.5 REST API Server-Side Request Forgery Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco TelePresence
VCS or Expressway Series on the remote host contains a vulnerability
in the web interface of Cisco Expressway Series and Cisco TelePresence
Video Communication Server (VCS) software could allow an authenticated,
remote attacker to trigger an HTTP request from an affected server to
an arbitrary host. This type of attack is commonly referred to as 
server-side request forgery (SSRF).");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvn33987");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190206-rest-api-ssrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee44583b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 12.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1679");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:expressway_software");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include("vcf.inc");

app = "Cisco TelePresence Device";

app_info = vcf::get_app_info(app:app, port:port, kb_ver: 'Cisco/TelePresence_VCS/Version');

constraints = [
  { "min_version" : "8.7", "fixed_version" : "12.5" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);


