##
# (C) Tenable Network Security, Inc.
##

include("compat.inc");

if (description)
{
  script_id(112217);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/10");

  script_cve_id("CVE-2018-0409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg97663");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180815-ucmimps-dos");

  script_name(english:"Cisco Unified Communications Manager Denial-of-Service Vulnerability (DoS)");
  script_summary(english:"Checks the Cisco Unified Communications Manager version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Unified Communications Manager is affected
by a Denial-of-Service vulnerability. Please see the included Cisco BIDs
and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180815-ucmimps-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb165fe3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg97663");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvg97663.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0409");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}


include('vcf.inc');

app = 'Cisco Unified CM IM&P';
get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::get_app_info(app:app);

# 11.5(1)SU4: https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/11_5_1/SU4/cucm_b_release-notes-cucm-imp-1151su4/cucm_b_release-notes-cucm-imp-1151su4_chapter_00.html
# The first fixed release for 10.5(2) is missing an SU number, but BID has 10.5(2.25100.1)
constraints = [
  { 'min_version' : '0', 'fixed_version' : '10.5.2', 'fixed_display' : '11.5.1.14900-32' },
  { 'min_version' : '10.5.2', 'fixed_version' : '10.5.2.25100.1'},
  { 'min_version' : '11.0.1', 'fixed_version' : '11.5.1.14900.32' },
  { 'min_version' : '12.0.1', 'fixed_version' : '12.0.1.12000.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
