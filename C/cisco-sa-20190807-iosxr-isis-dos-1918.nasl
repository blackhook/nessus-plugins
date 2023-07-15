#TRUSTED 0885abc917866bed305d7c52e7ebd5c6fc0ea25c4d4e62f75aa8a89b53ce1b04a57e802e3dc161a315ab5e9764f684fa0807e94cf9e26cd7d1f0bee06bab0b8e6b299cca8fc81f2f81c303cf226c390bd64d172b81a8a5d4ed4799253e3c7235519795631dd742eee1a50d2d2ab23e3c6ab461610aa6c7a55d64e78388b3c1b4fab04e7672c3d42908753e4352fec494c58816c0a129dddea75c990b8d364e4ef1f6405e3a91bdb30f176c11e556dc832d761a5f1a49b8068366314adde28d084085474640005713049294ce25f8a3dec5ae5c722b17e4c0f2c52466b39fd34b834b821558dc55b787bd89c25503263d8706bf9cc5fd9b296dfe3acb17df4db1bc22ce7adcd36594150b38f727c70537b72a76c0fca90f9d0bf1bdb01c023c4c3900228bacf9ef2c86c98e9a029d229575f1792e6afe9955d2219867b574a8ba4052251ab5c4a06cf2f3b16c629d25fc89e12048bb5abdc2f03136f9d79d6fb7d84deb4ffcad7ff76a3b37bf99665382c9242346c01990a98fc102a1450f9167a505e6501301154e08e410ec54280d8b55efc3ec7dca40426c9b2e4e927b739510e0aaead58eb687f53eb510f1a396ec4732055a2c5734956178d68de09dae901a344b00236e8742f36cded1ad68dc5f101505cdc0d32635dd7aa8fd752bd9dd594a551440ad5793ede6bc52c65cb7a2271464ba7d3fa8d7f610d19a338191a5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127900);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2019-1910", "CVE-2019-1918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp49076");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp90854");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-iosxr-isis-dos-1910");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190807-iosxr-isis-dos-1918");

  script_name(english:"Cisco IOS XR Software Intermediate System-to-Intermediate System Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XR Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR Software is affected by multiple vulnerabilities:

  - A vulnerability in the implementation of the Intermediate System-to-Intermediate System (IS-IS)
  routing protocol functionality in Cisco IOS XR Software could allow an unauthenticated attacker
  who is in the same IS-IS area to cause a denial of service (DoS) condition. The vulnerability is
  due to incorrect processing of crafted IS-IS link-state protocol data units (PDUs).
  An attacker could exploit this vulnerability by sending a crafted link-state PDU to an affected
  system to be processed. A successful exploit could allow the attacker to cause all routers within
  the IS-IS area to unexpectedly restart the IS-IS process, resulting in a DoS condition. This
  vulnerability affects Cisco devices if they are running a vulnerable release of Cisco IOS XR
  Software earlier than Release 6.6.3 and are configured with the IS-IS routing protocol. Cisco has
  confirmed that this vulnerability affects both Cisco IOS XR 32-bit Software and Cisco IOS XR 64-bit
  Software. (CVE-2019-1910)

  - A vulnerability in the implementation of Intermediate System-to-Intermediate System (IS-IS)
  routing protocol functionality in Cisco IOS XR Software could allow an unauthenticated attacker
  who is in the same IS-IS area to cause a denial of service (DoS) condition. The vulnerability is
  due to incorrect processing of IS-IS link-state protocol data units (PDUs).
  An attacker could exploit this vulnerability by sending specific link-state PDUs to an affected
  system to be processed. A successful exploit could allow the attacker to cause incorrect calculations
  used in the weighted remote shared risk link groups (SRLG) or in the IGP Flexible Algorithm. It
  could also cause tracebacks to the logs or potentially cause the receiving device to crash the IS-IS
  process, resulting in a DoS condition. (CVE-2019-1918)

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-iosxr-isis-dos-1910
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e181e06");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190807-iosxr-isis-dos-1918
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cf9e486");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp49076
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22433b62");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp90854
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec503ab3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvp49076 and CSCvp90854");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1910");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');
if (report_paranoia < 2) audit(AUDIT_PARANOID);

vuln_ranges = [
   {'min_ver' : '0.0',  'fix_ver' : '6.6.3'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp49076 and CSCvp90854'
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_ranges:vuln_ranges
  );
