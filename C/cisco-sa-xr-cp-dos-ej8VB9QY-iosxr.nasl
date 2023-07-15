#TRUSTED 009d0507f37ee3604a1a10ce305f8eaedf6978414c54bc6b1ece11e7cf4bad2db686670141bc7f8830b90f07d61f517b4fccb404af29c780522433d33449d829a28498cea0eab05f1f4353087f26f764bd005c0266e6ec3d0dd179dfa7713ac721bb2c75602aa7fde2b8e81e55be409b3d8851200c3925c5b56cf340564000b7c7e3b5a45f498a7722254948b1f81565269c647b98b2e63def0da5ebe1c35a8a90a72acdabb3009ee673ba516b26ad39d71b17e16aa395c68d2e2d8d25f7951f939867b30abdc4c470e5e4ca4062eac106831257c31eb7dd0ac6f34be6851eb2cfefe588d94f791d048c11363d6b005d15092a4369724837a8e9cab2e5e8e7fe7652a2ec78752a7ce50542c83af504c6707140e256d88f1ae99fc556f4a69f734c3d91dcbe662c0d192156d6dfbe63ceee18570e9425f5735769f4efbd05b5d2f57c195ad749f70243edaf40db237ecf80b3418f163ccd196b361d1725d522b3c4cf54f4b97a3516c549baac48fd62494a9b7f9208dec9f263c3ee2abe1c1155688180bd91128a2b0cfd152aa12c1db83f79df809317d185d4f2c8ab9f8bd2f01be90bcc164fef3771a94096b67957dd5f4943faa5d086980a3b41c51d1e999a269bdaf9e3b546eb31a7fc9052281b6a03e4eb201495fb829f35a58097cc200d70799468b1e63e3c542b429ac74ba90bcd57263c5eadaa8d6dbe81daaf43c539
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142890);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2020-26070");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv09115");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xr-cp-dos-ej8VB9QY");
  script_xref(name:"IAVA", value:"2020-A-0526-S");

  script_name(english:"Cisco IOS XR Software for ASR 9000 Series Slow Path Forwarding DoS (cisco-sa-xr-cp-dos-ej8VB9QY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XR is affected by a denial of service (DoS) vulnerability in the ingress
packet processing function due to improper resource allocation when processing network traffic in software switching
mode (punted). An unauthenticated, remote attacker can exploit this, by sending specific streams of Layer 2 or Layer 3
protocol data units (PDUs) to an affected device, in order to cause a DoS condition on the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xr-cp-dos-ej8VB9QY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd73ce5d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv09115");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv09115");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26070");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model) || 'ASR9' >!< model)
  model = toupper(product_info.model);

# Vulnerable model list
if (model !~ 'ASR9([0-9]{3}|K)')
    audit(AUDIT_DEVICE_NOT_VULN, product_info.model);

bid = 'CSCvv09115';
smus['6.4.2'] = bid;
smus['6.5.3'] = bid;

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.7.2'},
  {'min_ver' : '7.0', 'fix_ver' : '7.1.2'}
];


reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bid,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
