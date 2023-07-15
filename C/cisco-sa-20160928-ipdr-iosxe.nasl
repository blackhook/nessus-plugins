#TRUSTED 5e811b4e9e379bc8dc3111f640020dab4a7a7378cc4dc5e246e3852515ad828d2faf1aaae6f7156503d74b2dfee10cc6ddaaf675b62f5cdaff27f52029272547b8dcd7fc4afbefeb441cbfa78d2966efe29b2e632be0b96dea8d7dcff77b92337abf162ab038fa3a25988205ef0480eed01eed1a580f6838973cc1420f7dd423ade08717bb44ac75bebbd24db3f5aa4bf93efc66e0e9d3761594802e06b98c0cf477de80db31079004744496d98e313ed4032a83e898514aca6e5a5485c774a4b1a7ec55e831b37953ea94e3fc436b29968e0afdad1f05004085e4c8fda7fdac00e617c31bd51522c5cbcc43dbcf3ca73107cf5ba833f24abe2664075d7c4c1b979317bff868fce8ec18ca03133bbb86a7899c78113c6976ead6e9e7adf4c9746cc1f03b53581b98d1cdcb0dd462277739091e810f91a885cdd8b932f0f69a730f9caac5bd205c8237c7df96c18f2344eead6f099998a1c474c39cbf8f8e8d44b977ac5f59f6f3b8b55a254ad36f4deb0e6313a325adfcce780d6b58548eb0fe39d0211e9d2835dcf9536401595eb0ff6ffa43d18c7b26205827aef4eb40aa3d0a78b5b15b5884e32b0415046e506f52f6125700aca046067dcd99391f5a74158f329588e4a05790b18fe6db691ce1537e0d5f0e1ec7e52a8885313f6a1b308da2a4463c7c505a0781b5255cec5fb7930786d33c6686c1651c4867dc1bbcaa10
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130762);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2016-6379");
  script_bugtraq_id(93205);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu35089");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-ipdr");

  script_name(english:"Cisco IOS XE Software IP Detail Record DoS (cisco-sa-20160928-ipdr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the IP Detail Record (IPDR) due to improper handling of IPDR packets. An unauthenticated, remote attacker can exploit
this, by sending crafted IPDR packets, to cause the device to reload and stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-ipdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3196a03e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuu35089");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuu35089.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Checking models with regex, since ccf only does explicit ver list
#
# Cisco cBR Series Converged Broadband Routers
# Cisco uBR7200 Series Universal Broadband Routers - not a specific model on the software download page. 
# https://www.cisco.com/c/en/us/support/docs/broadband-cable/cable-modem-termination-systems-cmts/16044-7200ubr.html
# suggests that the last 2 digits might be free.
# Cisco uBR7225VXR Universal Broadband Routers - a specific model on the software download page, uBR7246VXR also exists
# Cisco uBR10000 Series Universal Broadband Routers - only uBR10012 seen on software download page

model = get_kb_item_or_exit('Host/Cisco/IOS-XE/Model');
if(
    model !~ '^cBR' &&
    model !~ '^uBR7225VXR' &&
    model !~ '^uBR72[0-9]{2}([^V]|$)' &&
    model !~ '^uBR100[0-9]{2}'
)
  audit(AUDIT_DEVICE_NOT_VULN, model);

version_list = make_list(
  '3.10.4S',
  '3.12.0aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1xbS',
  '3.15.1cS',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '3.18.3bSP'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ipdr_exporter'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCuu35089',
  'cmds'     , make_list('show ipdr exporter')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting, 
  vuln_versions:version_list
);
