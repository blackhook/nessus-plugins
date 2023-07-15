#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127916);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-1750");
  script_bugtraq_id(107607);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk24566");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-evss");

  script_name(english:"Cisco IOS XE Software Catalyst 4500 Cisco Discovery Protocol Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is
affected by following vulnerability

  - A vulnerability in the Easy Virtual Switching System
    (VSS) of Cisco IOS XE Software on Catalyst 4500 Series
    Switches could allow an unauthenticated, adjacent
    attacker to cause the switches to reload.The
    vulnerability is due to incomplete error handling when
    processing Cisco Discovery Protocol (CDP) packets used
    with the Easy Virtual Switching System. An attacker
    could exploit this vulnerability by sending a specially
    crafted CDP packet. An exploit could allow the attacker
    to cause the device to reload, resulting in a denial of
    service (DoS) condition. (CVE-2019-1750)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-evss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04399ca8");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk24566");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk24566");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1750");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

# e.g. Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software (cat4500e-UNIVERSALK9-M), Version 03.03.00.SG RELEASE SOFTWARE (fc3)
# model string is 'Catalyst 4500 L3 Switch Software (cat4500e-UNIVERSALK9-M)'
if (device_model !~ "cat" || product_info.model !~ "45[0-9]{2}"  )
  audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9E',
  '3.6.8E',
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
  '3.6.10E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E',
  '16.9.2h'
);

workarounds = make_list(CISCO_WORKAROUNDS['vss']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk24566'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
