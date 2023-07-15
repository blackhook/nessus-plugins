#TRUSTED 1487e95a2f049d00576ba6974a604471df4b901970927b7ec7fa973c446bbb660f871059a6dd5d15e2a712a4fb8dea5abf67d3ee563c441abc218c20e642aeb17713c09e5d1a3065b56c93de6aa0b3559261fc35fb5b4b89908c1c587e470aa80782449d77b18daa7e7b9d07e6899813ce959a3181bfb86f4c6ee20f75bdd63daab9330bf8e4f4d832eacc257271110ed8d7636f71c2b15ae27715226a331645eeb44f9a501c74a8a6f9a9f863d3b82cabe02f99c50c4fb15fb7abd6c6df6f36ed1226a498b63a00ccca40f829226a67d733313f37b4a38ac8d339e47fda9d1453cd13b559ed13573f7a754a677f0966994f9b9e74e2187947daa3fa92b6885c3261b33958c8525fc9cde7bc089a97cf6e6ff048fe4fe08b1f256ad62008aa97800fb36dfb9a9036ca9d010fe06c9e74049800a8b64947cb2082d0fe0b4eefded71aeb6a16151bdde8f789f5c009684ef1f0178d0bed3999da4065cea4a8cdef3f922e241f3ba81765a3c7399a14f15c7149972f549f34eb48cfe616c24afb2106269501ab7f3e735445ad13cccd4e3ce4c69a17fdaa68b3015b3d168ffa1ead897930583a5e1e3ef2f6c0a6891454c3c708af4c8f6a83fe7c9c1f8ebea9ec1d4ff1334d27142814deeda725a6155b2c0c4990cf8240b4a2285c625a4be21b8a1af24a9460dc4ff2ccc5f683ce4ca1969556ded5c0722bc705fb49e853713111
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148106);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2021-1453");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw36680");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-cat-verify-BQ5hrXgH");

  script_name(english:"Cisco IOS XE Software for the Catalyst 9000 Family Arbitrary Code Execution (cisco-sa-ios-xe-cat-verify-BQ5hrXgH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-cat-verify-BQ5hrXgH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01d217cf");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw36680");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw36680");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1453");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info.model);
    
# Vulnerable model list
if ((model !~ 'cat' || (model !~ '9400')) &&
    (model !~ 'cat' || (model !~ '9500-')) &&
    (model !~ 'cat' || (model !~ '9600')))
    audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.6',
  '16.6.7',
  '16.6.8',
  '16.7.1',
  '16.8.1',
  '16.8.1a',
  '16.8.1s',
  '16.9.1',
  '16.9.1s',
  '16.9.2',
  '16.9.2s',
  '16.9.3',
  '16.9.3s',
  '16.9.4',
  '16.9.5',
  '16.9.6',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.3',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.4.1'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvw36680',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
