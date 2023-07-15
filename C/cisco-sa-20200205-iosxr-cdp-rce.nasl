#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133603);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-3118");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr09190");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200205-iosxr-cdp-rce");
  script_xref(name:"IAVA", value:"2020-A-0041-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0016");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"Cisco IOS XR Software Cisco Discovery Protocol Remote Code Execution Vulnerability (cisco-sa-20200205-iosxr-cdp-rce)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XR Software is affected by a remote code execution vulnerability
within the Cisco Discovery Protocol due to improper validation of string input. An unauthenticated, adjacent
attacker can exploit this to bypass authentication and execute arbitrary commands with root privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200205-iosxr-cdp-rce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9623904");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr09190");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr09190.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3118");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

if ('ASR9' >< model && 'X64' >!< model)
{
  pies = make_array(
    '6.4.2', 'asr9k-px-6.4.2.CSCvr78185',
    '6.5.3', 'asr9k-px-6.5.3.CSCvr78185'
  );
}
else if ('ASR9' >< model)
{
  pies = make_array(
    '6.5.3', 'asr9k-x64-6.5.3.CSCvr78185'
  );
}
else if ('NCS5500' >< model)
{
  pies = make_array(
    '6.5.3', 'ncs5500-6.5.3.CSCvr78185'
  );
}
else if ('NCS540' >< model && 'L' >!< model)
{
  pies = make_array(
    '6.5.3', 'ncs540-6.5.3.CSCvr78185'
  );
}
else if ('NCS6' >< model)
{
  pies = make_array(
    '5.2.5', ' ncs6k-5.2.5.CSCvr78185'
  );
}
else if ('XRV9' >< model || 'XRV 9' >< model)
{
  pies = make_array(
    '6.6.2', 'xrv9k-6.5.3.CSCvr78185'
  );
}
else if ('NCS560' >< model)
{
  pies = make_array(
    '6.6.25', 'ncs560-6.6.25.CSCvr78185'
  );
}
else if ('CRS-PX' >< model)
{
  pies = make_array(
    '6.4.2', 'hfr-px-6.4.2.CSCvr78185'
  );
}
else if ('NCS5k' >< model)
{
    pies = make_array(
    '6.5.3', 'ncs5k-6.5.3.CSCvr78185'
  );
}
else if ('White box' >< model)
{
    pies = make_array(
    '6.6.12', 'iosxrwbd-6.6.12.CSCvr78185'
  );
}
else if ('NCS540L' >< model)
{
    pies = make_array(
    '7.0.1', 'ncs540l-7.0.1.CSCvr78185'
  );
}

# Check for patches
version = product_info['version'];
if (!empty_or_null(pies) && !empty_or_null(pies[version]))
{
  fixed_ver = product_info['version'] + ' with patch ' + pies[version];
  if (get_kb_item('Host/local_checks_enabled'))
  {
    buf = cisco_command_kb_item('Host/Cisco/Config/show_install_package_all', 'show install package all');
    if (check_cisco_result(buf))
    {
      if (pies[version] >< buf)
        audit(AUDIT_HOST_NOT, 'affected since patch '+pies[version]+' is installed');
    }
  }
}

vuln_ranges = [
  {'min_ver' : '6.6.1', 'fix_ver' : '6.6.3'},
  {'min_ver' : '6.6.25', 'fix_ver' : '7.0.2'}
];

workarounds = make_list(CISCO_WORKAROUNDS['cdp']);
workaround_params = make_list();

if (!empty_or_null(fixed_ver))
  fixed_ver = fixed_ver + ' or upgrade to 6.6.3 / 7.0.2';
else
  fixed_ver = 'Upgrade to 6.6.3 / 7.0.2';

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr09190',
  'fix'      , fixed_ver
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  router_only:TRUE
);
