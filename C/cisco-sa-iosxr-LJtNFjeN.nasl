#TRUSTED 7b1398efaf7822fa4d12c47a60f4b4120fda37ac5d53e7c422d05fadf7f5ef144d285eff0c6c02a53d49442d575026bf643180a0f6aff657dc1176a94a17181475c4bcc2c8c5f3fbd38949331732580c6ffca31e643b07378e3ddf4bc9324e78f9e0987cf89a1f59fc06e89827bacfd6f3ca69f22cdcae342345e48344c185712f4181548ff2c1b364bd3ec4a158645973746c83158e6b45b57f5c5d702380d05f55106fae01fa4c7ea007235f04b644a352a270e3b67686f03b2399c96733e340a3b8b972c0320ad4372158f8b3dcd750ea07adf9a0f9a2b7e3515aa6a22e901ec033db11b5bff091b69420ab871b1af576293d1817245f956fd85d86330b7517ef657e871a7b382be54de2ef26a9b4b24be1fa8f9bb9d0fbcabe90dc41aed174bfca5019fa06ca5f419cb1cd695125a2cefca54a9965df53b2d938057093942408c0724f190c8c9462c04a6cb457e55d9c6dab3feb514a1dee215cf94e9d1df817be4abb32d061cc2f1338a9a2b2b647b190391ce7a5d55ecc5c4bc076e168eb0fb27665243064a7d52558cab25eba31b07c58723cb223db5cb4b49c4ee7e22dd861c32084ecf920531cf0a276a75c0cd50486e758dbadb086ae08c7580f91eea6af8d68bca1ba554d6522849bcb330745050e001b118de367827eeda2674aa3154bd5516c4e77c238e23c8eaa276101a2638dc0ff94210407da42fe9ab94b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140793);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/10");

  script_cve_id("CVE-2020-3473");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs12604");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-LJtNFjeN");
  script_xref(name:"IAVA", value:"2020-A-0374-S");

  script_name(english:"Cisco IOS XR Software Authenticated User Privilege Escalation (cisco-sa-iosxr-LJtNFjeN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by a privilege escalation vulnerability in
task group assignment for a specific CLI command due to incorrect mapping to task groups. An attacker could exploit
this vulnerability by first authenticating to the local CLI shell on the device and using the CLI command to bypass
the task group–based checks. A successful exploit could allow the attacker to elevate privileges and gain full
administrative control of the device. There are workarounds that address this vulnerability.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-LJtNFjeN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d85a259");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs12604");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs12604");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3473");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

if (model =~ "8[0-9]{3}") // 8000 Series Routers
{
  vuln_ranges = [
    { 'min_ver' : '5', 'fix_ver' : '7.0.12' },
    { 'min_ver' : '7.2', 'fix_ver' : '7.2.1' }
  ];
}
else if ("NCS4K" >< model || model =~ "NCS4[0-9]{3}") // Network Convergence System 4000 Series
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '6.6.3' }
  ];
  smus['6.5.29'] = 'CSCvs12604';
}
else if (
     'XRV9K' >< model || model =~ "XRV9[0-9]{3}" || "XRV 9" >< model // IOS XRv 9000 Router
  || 'NCS540' >< model || 'NCS560' >< model // Network Convergence System 540/560 Routers
  || 'NCS55' >< model || model =~ "NCS55[0-9]{2}" // Network Convergence System 5500 Series
  || 'NCS6K' >< model || model =~ "NCS6[0-9]{3}") // Network Convergence System 6000 Series
{
  vuln_ranges = [
    { 'min_ver' : '5', 'fix_ver' : '6.6.3' },
    { 'min_ver' : '7.0', 'fix_ver' : '7.0.2' },
    { 'min_ver' : '7.1', 'fix_ver' : '7.1.1' }
  ];
}
else audit(AUDIT_HOST_NOT, 'an affected model');

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvs12604',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
