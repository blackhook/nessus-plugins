#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135766);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2020-3239",
    "CVE-2020-3240",
    "CVE-2020-3243",
    "CVE-2020-3247",
    "CVE-2020-3248",
    "CVE-2020-3249",
    "CVE-2020-3250",
    "CVE-2020-3251",
    "CVE-2020-3252"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs53493");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs53496");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs53500");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs53502");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56399");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56400");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs56401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs69022");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs69171");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39489");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39526");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39535");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39555");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39561");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39565");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39575");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt39580");

  script_name(english:"Cisco UCS Director and Cisco UCS Director Express for Big Data Multiple Vuulnerabilities (cisco-sa-ucsd-mult-vulns-UNfpdW4E)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote host is running a version of Cisco UCS Director that is affected by
multiple vulnerabilities in the REST API which allow a remote attacker to bypass authentication or conduct directory
traversal attacks on an affected device, including the following:

  - An unauthenticated, remote attacker can bypass authentication and execute arbitrary actions with
    administrative privileges on an affected device due to insufficient access control validation. An
    attacker can exploit this vulnerability by sending a crafted request to the REST API, allowing the
    attacker to interact with the REST API with administrative privileges. (CVE-2020-3243)

  - An unauthenticated, remote attacker can execute arbitrary code with root privileges on the underlying
    operating system due to improper input validation. An attacker can exploit this by crafting a malicious
    file and sending it to the REST API. (CVE-2020-3240)

  - An unauthenticated, remote attacker can bypass authentication and execute API calls on an affected device
    due to insufficient access control validation. An attacker can exploit this by sending a request to the
    REST API endpoint in order to cause a potential Denial of Service (DoS) condition on the affected device.
    (CVE-2020-3250)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs53493");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs53496");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs53500");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs53502");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs56399");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs56400");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs56401");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs69022");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs69171");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvt39489");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvt39526");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvt39535");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvt39555");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvt39561");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvt39565");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvt39575");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvt39580");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucsd-mult-vulns-UNfpdW4E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbbadbc7");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3248");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Cisco UCS Director Directory Traversal");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco UCS Director Cloupia Script RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ucs_director");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_director_detect.nbin");
  script_require_keys("Host/Cisco/UCSDirector/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco UCS Director', kb_ver:'Host/Cisco/UCSDirector/version');

fix = '6.7.4.0';
constraints = [
  { 'equal' : '6.0.0.0', 'fixed_display': fix},
  { 'equal' : '6.0.0.1', 'fixed_display': fix},
  { 'equal' : '6.0.1.0', 'fixed_display': fix},
  { 'equal' : '6.0.1.1', 'fixed_display': fix},
  { 'equal' : '6.0.1.2', 'fixed_display': fix},
  { 'equal' : '6.0.1.3', 'fixed_display': fix},
  { 'equal' : '6.5.0.0', 'fixed_display': fix},
  { 'equal' : '6.5.0.1', 'fixed_display': fix},
  { 'equal' : '6.5.0.2', 'fixed_display': fix},
  { 'equal' : '6.5.0.3', 'fixed_display': fix},
  { 'equal' : '6.5.0.4', 'fixed_display': fix},
  { 'equal' : '6.6.0.0', 'fixed_display': fix},
  { 'equal' : '6.6.1.0', 'fixed_display': fix},
  { 'equal' : '6.6.2.0', 'fixed_display': fix},
  { 'equal' : '6.7.0.0', 'fixed_display': fix},
  { 'equal' : '6.7.1.0', 'fixed_display': fix},
  { 'equal' : '6.7.2.0', 'fixed_display': fix},
  { 'equal' : '6.7.3.0', 'fixed_display': fix}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

