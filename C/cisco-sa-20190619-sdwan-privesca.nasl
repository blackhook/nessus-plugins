#TRUSTED 9b8ff19567c23d1405d8d4e05830b7fc079ee0998cb8ff8ee4a37552d83b8113d96323a136070a12177a7fe2b8c2dd3a285d9c10cb7cfe85c3f72f6af651064067483b53a0d676245767a9fca522a087f3896e7dc9ee9a778b1d9c2d10575eb9f0df36268177956e9ddfddd2866003c09a360454e9f230ee06ff49cbf453a71ceabd1081ba571c6f1a80348ac804ec04a96fb83412e9ece61c6e7b7f17929289d7f2fc51aa8a66cc4d2478f571f9efc2b315695e4fa07ab328391ae6040fd27ce3c0503ba23bedc51ae60ba81896b30b01e5b3331bfa924ce6b4c0725a345fbd17837a202c10a0bfef8ef26546700302106c0f2544af2ffb53307c6f23582db2fbbba69d78935da48eb313c375d80ff36599a9c9a73dbad0aaf85ac08c30238d568726944515658812801f5b2a34923b3dedd81e19a0e28b320ae168ba1dad0c772f3d55d7a9e56ecf46898b3109c8eedb1b178d19f0879a4014bc8dff2381694f8a078aafa59ab72608b65062c0ff652003779062745d73abcba07c91d8fa33def53a3b9f908ff2569506c9b3e11ba000dfe17dd4a90cfca6800204648fcfbab153c00112026b34eca6b8701bd336253ff08e79d1191e1c51ad2df1cfda4fb2eb558d5afb2d04c437a530bc4dccada0d9541a458e4d4d883b79632c18b0cd31e2dba2d3a4491114a1bbca7e1264b235d2fccbda145da5fade2651a0daa23eb5
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147878);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2019-1625");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69756");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190619-sdwan-privesca");

  script_name(english:"Cisco SD-WAN Solution Privilege Escalation (cisco-sa-20190619-sdwan-privesca)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Solution is affected by a vulnerability due to insufficient
authorization enforcement. An authenticated, local attacker can exploit this, by authenticating to the targeted device
and executing commands, in order to elevate lower-level privileges to root.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-sdwan-privesca
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83d43c6f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69756");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69756");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0.0',   'fix_ver':'18.3.6' },
  { 'min_ver':'18.4',  'fix_ver':'18.4.1' },
  { 'min_ver':'19.0',  'fix_ver':'19.1.0' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69756',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
