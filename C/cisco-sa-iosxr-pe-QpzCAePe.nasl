#TRUSTED 4c631f072de11526a50b85809ecbca67906059028812e4fe8e68c2304a1892d13537cf5f51fcbe9af4b30f8c1a6ceafaa87b5a48317bb40e8a7e01dd6be91f5d94038bb8726fdc0baf2905f9da65c5ed0668979ce9a31a617a216d1f56fb285fa41c658d8303c68f7fcd15d445d7cd0abfb1a9b07336fb8630f9d1b63b1748047bd0054f8a1b7bebc3bcc5cab232a755291449ef0b0e8e664009ef8c75e06b183dbf30045cc543aab4a6b3b05eaec1e53868eb3e1dca5b8b3e11a155cbab2f4e8ebeb7bf2bab42466cf6c9a8939575c7e714046fa3f3f80b6349adcd55a97be118ae043f13b9f7669a5afaf639b47ab06ba08a7a0723900a801033dd7007144b2200b33352ad28a9d0926ccd7e48e0c22749965565befb7e45177ea73c1c979e1e49df20761ade96147c08b9ffcdf3c248f477985bcaf07cd676915a003fd2ea06d5d6260292c2e8d505f9e58e99fe893ae2e01cbc0af6c3e3f8de3794a28b10a5a10eb8adcd71fe13d06f980dadc67322eb128f726158784eb49cfe9f8dd3c3d1396defca735bc5f4111b09b07228dbdf149090044fb42bd00b17c05e3dfec6c1ad40b84a8bad0280d8b8a20917207f804f1af900753e87741f6688e4a37f8c3841be0cada2897140ae2e3e3b3aca1f92a082a10b63a66fd0f9dbf1bbd9abb1661d0d1db15f32d448f492f01070930501a430040ea6256dc6723eee4fa500ba
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147816);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1370");
  script_xref(name:"IAVA", value:"2021-A-0062-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs35027");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-pe-QpzCAePe");

  script_name(english:"Cisco IOS XR Software for 8000 Series Routers Network Convergence System 540 Series Routers Privilege Escalation (cisco-sa-iosxr-pe-QpzCAePe)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software for the Cisco 8000 Series Routers and Network 
Convergence System 540 Series Routers running NCS540L software images is affected by an privilege escalation 
vulnerability in its CLI command due to insufficient validation of command line arguments. To exploit this 
vulnerability, an attacker would need to have a valid account on an affected device. An authenticated, local 
attacker can exploit this vulnerability by authenticating to the device and entering a crafted command at the prompt. 
A successful exploit could allow an attacker with low-level privileges to escalate their privilege level to root.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-pe-QpzCAePe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7175d10");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs35027");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs35027");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1370");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');

if (empty_or_null(model))
  model = product_info['model'];

model = toupper(model);

# 8000 Series Routers
if (model =~ "(8[0-9]{3}|8K)")
{
  vuln_ranges = [
    { 'min_ver' : '0.0', 'fix_ver' : '7.0.12' },
    { 'min_ver' : '7.2', 'fix_ver' : '7.2.1' }
  ];
}

# Network Convergence System 540 Series Routers
else if ('NCS540L' >< model)
{
  vuln_ranges = [
    { 'min_ver' : '7.0', 'fix_ver' : '7.1.2' }
  ];
  smus['7.1.2'] = 'CSCvs35027';
}

else audit(AUDIT_HOST_NOT, 'an affected model');

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs35027',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
