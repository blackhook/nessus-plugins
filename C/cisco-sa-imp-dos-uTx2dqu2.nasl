##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142496);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-27121");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv75814");
  script_xref(name:"CISCO-SA", value:"cisco-sa-imp-dos-uTx2dqu2");
  script_xref(name:"IAVA", value:"2020-A-0504-S");

  script_name(english:"Cisco Unified Communications Manager IM and Presence Service DoS (cisco-sa-imp-dos-uTx2dqu2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Communications Manager IM and Presence Service is affected by a
vulnerability due to improper handling of login requests. An authenticated, remote attacker can exploit this, by sending
a crafted client login request to an affected device, in order to cause the Cisco XCP Authentication Service to restart,
resulting in a DoS condition for new login attempts.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-imp-dos-uTx2dqu2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03a9966c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv75814");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv75814");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27121");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager_im_and_presence_service");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_cucm_imp_detect.nbin");
  script_require_keys("installed_sw/Cisco Unified CM IM&P");

  exit(0);
}

include('vcf.inc');

app = 'Cisco Unified CM IM&P';
get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::get_app_info(app:app);

# Version from https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU3/cucm_b_release-notes-for-cucm-imp-1251su3/cucm_m_about-this-release.html
constraints = [
  {'min_version' : '12.5.1.13900.17', 'fixed_version' : '12.5.1.13900.18', 'fixed_display' : 'See vendor advisory'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

