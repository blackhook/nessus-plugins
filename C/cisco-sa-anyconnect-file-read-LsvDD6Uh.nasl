##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142589);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2020-27123");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv66094");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-file-read-LsvDD6Uh");
  script_xref(name:"IAVA", value:"2020-A-0505-S");

  script_name(english:"Cisco AnyConnect Secure Mobility Client for Windows Arbitrary File Read (cisco-sa-anyconnect-file-read-LsvDD6Uh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco AnyConnect Secure Mobility Client is affected by a arbitrary file read
vulnerability. The vulnerability is due to an exposed IPC function. An unauthenticated, local attacker could exploit
this vulnerability by sending a crafted IPC message to the AnyConnect process on an affected device. A successful
exploit could allow the attacker to read arbitrary files on the underlying operating system of the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-file-read-LsvDD6Uh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?242bf0a3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv66094");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv66094");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27123");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(749);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:TRUE);

constraints = [{ 'fixed_version' : '4.9.03047' }];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
