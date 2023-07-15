#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130174);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-12634");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq89223");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190821-ucs-imc-dos");
  script_xref(name:"IAVA", value:"2019-A-0312-S");

  script_name(english:"Cisco UCS Director Loggoff DoS (cisco-sa-20190821-ucs-imc-dos)");
  script_summary(english:"Checks the Cisco UCS Director version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote host is running a
version of Cisco UCS Director that is affected by a denial of service
vulnerability. An unauthenticated, remote attacker can exploit this to
cause all currently authenticated users to be logged off.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq89223");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190821-ucs-imc-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aae2ab8e");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID
CSCvq89223");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12634");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"combined");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/24");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ucs_director");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ucs_director_detect.nbin");
  script_require_keys("Host/Cisco/UCSDirector/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco UCS Director', kb_ver:'Host/Cisco/UCSDirector/version');

constraints = [
  { 'equal': '6.6.0.0', 'fixed_version': '6.7.3.0'},
  { 'equal': '6.6.1.0', 'fixed_version': '6.7.3.0'},
  { 'min_version': '6.7.0.0', 'max_version':'6.7.2.0', 'fixed_version': '6.7.3.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
