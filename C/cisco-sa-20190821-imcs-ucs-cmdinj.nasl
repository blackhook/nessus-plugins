#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129291);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/26  9:47:30");

  script_cve_id("CVE-2019-1936");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp19245");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190821-imcs-ucs-cmdinj");

  script_name(english:"Cisco UCS Director Authentication Bypass (cisco-sa-20190821-imcs-ucs-cmdinj)");
  script_summary(english:"Checks the Cisco UCS Director version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote host is running a
version of Cisco UCS Director that is affected by a command execution
vulnerability. An authenticated, remote attacker can exploit this to 
execute arbitrary commands as a root user.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvp19245");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190821-imcs-ucs-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c84fa5ca");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID
CSCvp19245");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1936");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco UCS Director Unauthenticated Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");


  script_set_attribute(attribute:"plugin_type", value:"combined");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ucs_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ucs_director_detect.nbin");
  script_require_keys("Host/Cisco/UCSDirector/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco UCS Director', kb_ver:'Host/Cisco/UCSDirector/version');

constraints = [
    { 'min_version': '6.0.0.0', 'fixed_version': '6.7.2.0', 'fixed_display':'6.7.3.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);