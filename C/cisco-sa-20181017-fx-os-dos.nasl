#TRUSTED a1f223876266d5f84d50092325d577eabe14add15964eadef563bfdf64b9ad4e890547e8e396e32e9697d045519fb2e95989ffcec2c143a75b0725bcd4f4907b08099c3a3a1923017e744220392a5a7b99c2a81ea18e3bb535ffcedab75b28f8531dd949ef9457e61947eeeb659b032fe1d8bb49a10ea87667ce1c7736cfe2ed50ff393507e25c4f287999f8e74e0c6a2aadeb31b0ad4025fec3998412c0ace13af571ca077289cadfe90826728ad3ab3659a38a8507194fc1dac261fb5bed0ca72ab5c48bb5cedb542e590b4fbaf4f80731f12e49898701463efde0cfc6bb04f4065984a69179ec8f6621b103ad932fc773fa11362a08a8f6f092a9328ec2eafb294c7e8494c1061037431502450690c2881c638142ed6c1a7d427d08cfb6855f7c101160a0f20a11941bb83708464a19c93a5b12c6cf3c41c255c3c2fe7109034a8ad00fc2198501941af2ea650410527a9acb99c6fd97a61d1d132c0671f42996b4cdb02bbbeb1e1cf1dd64e1e6bbfbfe65d971138bdfe802bb1b0066c53b0f12569ac7f82616ea4363f0defc19fdce4a2db40775a8e2ab5a84430abb41302e7e2f4300f44cf0ec7720b24bc4551a855da25c7aa386a791380cf477499ab8bc30d1769bd8fbaee9dc7201e9d58c1657d2663ed67e074b2343a0cf8b17e03c79ec8a0ccbcd1a9d9928176a46be12eafe94c6e3ad63c7adf017244d496a09fd
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134946);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/31");

  script_cve_id("CVE-2018-0395");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf23367");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181017-fxnx-os-dos");

  script_name(english:"Cisco FXOS Software Link Layer Discovery Protocol DoS (cisco-sa-20181017-fxnx-os-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco FX-OS Software due to improper input validation of
certain type, length, value (TLV) fields of the LLDP frame header. An unauthenticated, local attacker can exploit this
issue, by sending a crafted LLDP packet to an interface on the targeted device, to cause the system to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181017-fxnx-os-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3775192a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf23367");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvf23367");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

# check if 4100 series or 9300 series appliance
if (product_info['model'] =~ "^(41|93)[0-9]{2}$")
{
  vuln_ranges = [ {'min_ver' : '0.0', 'fix_ver' : '2.3'} ];
}
else
{
  audit(AUDIT_HOST_NOT, "a vulnerable model");
}

if (report_paranoia < 2) audit(AUDIT_PARANOID);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = [];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , "CSCvf23367",
  'version'  , product_info['version'],
  'fix'      , '2.3.1.58'
);

cisco::check_and_report(product_info:product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_ranges       : vuln_ranges
);
