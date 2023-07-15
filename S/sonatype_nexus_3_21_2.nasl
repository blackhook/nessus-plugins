#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154953);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-10199");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Sonatype Nexus Repository Manager 3.x < 3.21.2  RCE");

  script_set_attribute(attribute:"synopsis", value:
"The Nexus Repository Manager server running on the remote host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Sonatype Nexus Repository Manager server application running on the remote host is version 3.x prior
 to 3.21.2. It is, therefore, affected by a remote code execution vulnerability, which allows for an 
 attacker with any type of account on NXRM to execute arbitrary code by crafting a malicious request to NXRM.
 
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.sonatype.com/hc/en-us/articles/360044882533
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc1482dd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sonatype Nexus Repository Manager version 3.21.2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10199");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nexus Repository Manager Java EL Injection RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonatype:nexus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonatype_nexus_detect.nbin");
  script_require_keys("installed_sw/Sonatype Nexus");
  script_require_ports("Services/www", 8081);

  exit(0);
}

include('vcf.inc');
include('http.inc');

appname = 'Sonatype Nexus';
port = get_http_port(default:8081);

vcf::add_separator('-'); # used in parsing version for vcf
app = vcf::get_app_info(app:appname, webapp:TRUE, port:port);

constraints = [{'min_version' : '3.0', 'fixed_version' : '3.21.2'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);
