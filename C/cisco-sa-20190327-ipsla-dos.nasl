#TRUSTED 2e4d66779c6b87fed2b68a33039e824cb16dca8455bd49d86468c501595cfaa395c91fd2e7ed8a1891b5ce06606e319662914da04b41605bfcf4a4c3f1063d581ad1d275977e875d9a2e69a571d6452e37c8fbf8d9d006c656b0a18ec0cc66f127f8d7ad703b5aae23584934c93a986c08235881a137defc2710df49c3c049c60d256f26392285dcd36e5fa885ca4e52b0e68cf4371b74b04d085c8fe7311d8082a69943d261a12e5b8cc406930df93cac4d2dca2191f6a62b534ba435e1d2013944d77f99d40de9891263efac4a7fefe5c2a75b030ddbe2201f730fe530b0111d2d91c6eb1fe22dd25f0904cb69bddb0c47493715a347bb9ced67c9eb7da273f2cd7c70d6650435e991660684293efc94f900a9a55c434f1753663f483557e6991d95963050b491b934197c307a9f70c924ea3027fb8fb9d72e4e8d11f8667c29bba05ac39b23a88ba16558c2dbab1213ce3ed85ddb17420e6e8d1f48d62d35d9d93a69ff38c3f0fd7f4378b27cc3e9533751050d9328ff66cdf1cac6d090dc709112dd10ca776448489cb7880a282324f829636da1ab2634d5664cb9ce6879043e3300db8b206e29b6b7e89002c477a244390b3031fd6b688c1601a24e5c09501f258137e9b8243664765727d039641d52249282a22f681f8b95de6f0fdb017c3545147e72652bf23e7c1b75b6f62a4cd99b6bca32a3b6680dfec968e66e8e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128526);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/29");

  script_cve_id("CVE-2019-1737");
  script_bugtraq_id(107604);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf37838");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-ipsla-dos");

  script_name(english:"Cisco IOS and IOS XE Software IP Service Level Agreement Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability
in the processing of IP Service Level Agreement (SLA) packets by Cisco IOS Software and Cisco
IOS XE software, which could allow an unauthenticated, remote attacker to cause an interface
wedge and an eventual denial of service (DoS) condition on the affected device. The vulnerability
is due to improper socket resources handling in the IP SLA responder application code. An attacker
could exploit this vulnerability by sending crafted IP SLA packets to an affected device. An exploit
could allow the attacker to cause an interface to become wedged, resulting in an eventual denial of
service (DoS) condition on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-ipsla-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74b82563");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf37838");
  script_set_attribute(attribute:"solution", value:"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvf37838");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1737");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2S',
  '3.9.2E',
  '3.9.1aS',
  '3.9.1S',
  '3.9.1E',
  '3.9.0aS',
  '3.9.0S',
  '3.9.0E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2S',
  '3.8.2E',
  '3.8.1S',
  '3.8.1E',
  '3.8.0S',
  '3.8.0E',
  '3.7.8S',
  '3.7.7S',
  '3.7.6S',
  '3.7.5S',
  '3.7.5E',
  '3.7.4aS',
  '3.7.4S',
  '3.7.4E',
  '3.7.3S',
  '3.7.3E',
  '3.7.2tS',
  '3.7.2S',
  '3.7.2E',
  '3.7.1aS',
  '3.7.1S',
  '3.7.1E',
  '3.7.0bS',
  '3.7.0S',
  '3.7.0E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.2E',
  '3.6.1E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.5.3E',
  '3.5.2E',
  '3.5.1E',
  '3.5.0E',
  '3.4.8SG',
  '3.4.7SG',
  '3.4.6SG',
  '3.4.5SG',
  '3.4.4SG',
  '3.4.3SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.0SG',
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SE',
  '3.2.3SE',
  '3.2.2SE',
  '3.2.1SE',
  '3.2.0SE',
  '3.2.0JA',
  '3.18.4S',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0cE',
  '3.10.0S',
  '3.10.0E',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.2',
  '16.4.1',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ip_sla'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf37838'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
