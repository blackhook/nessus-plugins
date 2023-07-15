#TRUSTED 183aacc96b0dc01c79556ab13983a4bcbc25db5ce4ec0dee2d192e930fef2b78687226075bcf0b55a5957bcd135267c2a967e49f0e3aa4b0ec16730def77d2794a0d9768d0548121ccc4cd74716d268360abe3071a98e9bb2ceab81eea1595f89b0c2c2093331734216b796c61534a3a713b0cea808070dc9bd0bca5c30b07ccc10305c2d4854c6cc59f0ffac5fb30084a0ceda5314f98f654bb78353528a7136a5773b547e198ff7b5ebe41d20a43da5b24418748f59b55bd9ff8ff2b4286ae542670f9f4a8e3765f5de0685546d888fa06a679ce538b5e0788a96c4d47429327fdc24ad19703279b82f2d2a2d7426c93069be7d3290c75fd11be91a9a4fa8e88c94707fed630239a2402edc145f0302e9f109676e261699457e390ef15ec798c50035c21ef8a7ef53049940b700850bcae552848a39d9d2a1ad77ab3defccdfa0af321f47e08e51924bc5af1ea287fa088aef0f85c4e300ab622ddde6a3b616fcc4df3db90deb5c482f0139089fd410e74f0cd70fb9b5220ac3635c37078775c3179d6365e143958359a2904af7d4c7479d157bdc292b47d03be5a45922a37291cfed47ec19a7cea5885a510de9afe8e1f59859247281aa67f027b4156bc46456fc39faaed5477318a1395639fe3b3ff02fdcce57a11aef9b3a8fd9c74e145c068379a879c0f6f5788c95e53a2cb787a4dd74fc9ad17d7ec3feab837d19ada
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128281);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1780");
  script_bugtraq_id(108392);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01431");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01440");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92326");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92328");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92329");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-fxos-cmdinj-1780");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco NX-OS Software Command Injection Vulnerability (CVE-2019-1780)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cissco NX-OS Software is affected by a vulnerability that allows an
authenticated, local attacker with administrator credentials to execute arbitrary commands on the underlying operating
system of an affected device with elevated privileges. The vulnerability is due to insufficient validation of
arguments passed to certain CLI commands. An attacker could exploit this vulnerability by including malicious input as
the argument of an affected command. A successful exploit could allow the attacker to execute arbitrary commands on
the underlying operating system with elevated privileges. An attacker would need valid administrator credentials to
exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-fxos-cmdinj-1780
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d79e1307");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01431");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01440");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92326");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92328");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92329");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi01431, CSCvi01440, CSCvi92326, CSCvi92328, and 
CSCvi92329");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1780");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

cbi = '';

if ('MDS' >< product_info.device && product_info.model =~ '^90[0-9][0-9]')
  cbi = 'CSCvi01440';
else if ('Nexus' >< product_info.device)
{
  if (product_info.model =~ '^(3[05]|90)[0-9][0-9]')
    cbi = 'CSCvi01431, CSCvi92328';
  else if (product_info.model =~ '^(36|95)[0-9][0-9]')
    cbi = 'CSCvi92326';
  else if (product_info.model =~ '^(5[56]|60)[0-9][0-9]')
    cbi = 'CSCvi92329';
  else audit(AUDIT_HOST_NOT, 'affected');
}
else audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '6.0(2)A8(1)',
  '6.0(2)A8(2)',
  '6.0(2)A8(3)',
  '6.0(2)A8(4)',
  '6.0(2)A8(4a)',
  '6.0(2)A8(5)',
  '6.0(2)A8(6)',
  '6.0(2)A8(7)',
  '6.0(2)A8(7a)',
  '6.0(2)A8(7b)',
  '6.0(2)A8(8)',
  '6.0(2)A8(9)',
  '6.0(2)A8(10a)',
  '6.0(2)A8(10)',
  '6.2(2)',
  '6.2(2a)',
  '6.2(6)',
  '6.2(6b)',
  '6.2(8)',
  '6.2(8a)',
  '6.2(8b)',
  '6.2(10)',
  '6.2(12)',
  '6.2(18)',
  '6.2(16)',
  '6.2(14b)',
  '6.2(14)',
  '6.2(14a)',
  '6.2(6a)',
  '6.2(20)',
  '6.2(1)',
  '6.2(3)',
  '6.2(5)',
  '6.2(5a)',
  '6.2(5b)',
  '6.2(7)',
  '6.2(9)',
  '6.2(9a)',
  '6.2(9b)',
  '6.2(9c)',
  '6.2(11)',
  '6.2(11b)',
  '6.2(11c)',
  '6.2(11d)',
  '6.2(11e)',
  '6.2(13)',
  '6.2(13a)',
  '6.2(13b)',
  '6.2(15)',
  '6.2(17)',
  '6.2(19)',
  '6.2(21)',
  '6.2(20a)',
  '7.0(3)F3(1)',
  '7.0(3)F3(2)',
  '7.0(3)F3(3)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)I4(1)',
  '7.0(3)I4(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(4)',
  '7.0(3)I4(5)',
  '7.0(3)I4(6)',
  '7.0(3)I4(7)',
  '7.0(3)I4(8)',
  '7.0(3)I4(8a)',
  '7.0(3)I4(8b)',
  '7.0(3)I4(8z)',
  '7.0(3)I7(5a)',
  '7.0(3)I7(1)',
  '7.0(3)I7(2)',
  '7.0(3)I7(3)',
  '8.1(1b)',
  '8.2(1)',
  '8.2(2)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , cbi
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  switch_only:TRUE
);
