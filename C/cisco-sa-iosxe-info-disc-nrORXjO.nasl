#TRUSTED 9363b01a80d012d83b5d7f5cdb1c8c1a7a7c840e187165f0f28c59f48451d314fff197648e7f9bb1252f7118a3b845396db0096737c79101a1734b789f9347f123e5558440b2bd653161542fb36cdeb7696023420103ac5c215d9fc16a6421f383a89602cdb1cead016c904dc4f712c9530f8c645187c9e20d1e996455adcd9ec43319560fe09f2d0099b66c2ff3f93e852b2bae6548d0bc1cfd7f910ceb3297cd217ed73434bbc87c217b2db4f0298442daae64007f8adffdad4bae99d9bad9e833d67439a13d89dace7e79aca4aae5c79839034332d1e078e38a2a04d45ffc3118cd055e2065b4d1ca801a22f20eff4545fc05110b47cf184e77169434b96e7e9275739af3a8f6f6a6ff5ed8ca3b1a87e9ba7bc798fc6cbed6a0651bb42233e89fc7b05ad5d63aa80f44884b9bdcb9d851e9592383109223a86cd5d3137055ff3320b09bb51ade916820968ebafd51cc20e9d27146fb93b567b98722a918e917b55608e4e3374c467c2946d6331dfd7d3f96b7f5a966594a9ad2d2a841bdb11d025937b1479ee0ffe407bd323a4c6ea72792350040943b56de54795a0fbd313968f7f9f04c3c9ab136703638551e7307de1b1573a3575a6d2b945a0f3ca80d7c26d9a66ad9a1605e22cdd65d7ba211a485763d9eaf37e4bb858fca2a864a2a9a43ec11efa67aa0892aaa2827393db0fb15f282ee96c52d8fe49abce7563075
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166458);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2022-20864");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx64514");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx88952");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa53008");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa58212");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-info-disc-nrORXjO");
  script_xref(name:"IAVA", value:"2022-A-0390");

  script_name(english:"Cisco IOS XE ROM Monitor Software for Catalyst Switches Information Disclosure (cisco-sa-iosxe-info-disc-nrORXjO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE ROM Monitor Software for Catalyst Switches is affected by an
information disclosure vulnerability. A problem with file and boot variable permissions in the ROMMON password-recovery
disable feature of Cisco IOS XE ROM Monitor (ROMMON) Software could allow an unauthenticated, local attacker to reboot
the switch into ROMMON and enter specific commands through the console to recover the configuration or reset the enable
password.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-info-disc-nrORXjO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08a6dccb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx64514");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx88952");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa53008");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa58212");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvx64514, CSCvx88952, CSCwa53008, CSCwa58212");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20864");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(538);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# TODO update this section accordingly

var vuln_ranges = [];

switch (product_info)
{
  case product_info.model =~ "3[68][0-9][0-9]":
    vuln_ranges = [{'min_ver' : '0', 'fix_ver' : '16.12.7'}];
    break;
  case product_info.model =~ "92[0-9][0-9]":
    vuln_ranges = [{'min_ver' : '0', 'fix_ver' : '17.6.3', 'display_version':'17.6.3 / 17.8.1'}];
    break;
  case product_info.model =~ "9[3456][0-9][0-9]":
    vuln_ranges = [{'min_ver' : '0', 'fix_ver' : '17.8.1'}];
    break;
}

var workarounds = make_list(CISCO_WORKAROUNDS['rommon_password_recovery_enabled']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvx64514, CSCvx88952, CSCwa53008, CSCwa58212',
  'cmds'          , make_list('show version | include BOOTLDR', 'show romvar | include SWITCH_DISABLE_PASSWORD_RECOVERY'),
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  switch_only:TRUE
);
