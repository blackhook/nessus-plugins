#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140456);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/12");

  script_cve_id("CVE-2020-3182");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr98226");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webex-info-disc-OHqg982");

  script_name(english:"Cisco Webex Meetings Client for MacOS Information Disclosure (cisco-sa-webex-info-disc-OHqg982)");

  script_set_attribute(attribute:"synopsis", value:
"The remote videoconferencing software is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Meetings Client for MacOS is affected by an information 
disclosure vulnerability in the multicast DNS (mDNS) protocol configuration due to sensitive information being 
included in the mDNS reply. An unauthenticated, adjacent attacker can exploit this, by doing an mDNS query for a particular service against an affected device, to obtain sensitive 
information about the device on which the Webex client is running.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webex-info-disc-OHqg982
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c473ae16");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr98226");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr98226");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3182");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_cisco_webex_meetings_desktop_app_installed.nbin");
  script_require_keys("installed_sw/Cisco Webex Meetings", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');
get_kb_item_or_exit('Host/local_checks_enabled');
app = 'Cisco Webex Meetings';
app_info = vcf::get_app_info(app:app);

constraints = [
  { 'max_version' : '40.1.8.5', 'fixed_display':'Refer to Cisco Bug ID: CSCvr98226' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

