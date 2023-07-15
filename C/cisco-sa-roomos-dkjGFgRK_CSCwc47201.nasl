#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170018);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");

  script_cve_id("CVE-2023-20008");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc47201");
  script_xref(name:"CISCO-SA", value:"cisco-sa-roomos-dkjGFgRK");
  script_xref(name:"IAVA", value:"2023-A-0031-S");

  script_name(english:"Cisco TelePresence CE Arbitrary File Write (cisco-sa-roomos-trav-beFvCcyu)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Collaboration Endpoint Software is affected by an arbitrary
file write vulnerability. Due to improper access controls on files in the that are in the local system, a local
attacker can place a symbolic link in a specific location in the local file system to overwrite arbitrary files on
the affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-roomos-dkjGFgRK
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80b65db2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc47201");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc47201");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_collaboration_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");

  exit(0);
}

include('ccf.inc');

var app_name = 'Cisco TelePresence CE software';
var version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');
var device = get_kb_item_or_exit('Cisco/TelePresence_MCU/Device');
device = tolower(device);

if ('telepresence' >!< device && 'room' >!< device)
  audit(AUDIT_HOST_NOT, 'a vulnerable device');

var ver_list = split(version, sep:'.', keep:FALSE);
var max_ver_segs = max_index(ver_list);
var short_version;

# versions appear like ce9.13.0.990355df13a and ce10.13.1.3.dd7ec0ed589
if (max_ver_segs >= 5)
  short_version = pregmatch(pattern: "^(ce)(\d+(?:\.\d+){0,3})", string:version);
else
  short_version = pregmatch(pattern: "^(ce)(\d+(?:\.\d+){0,2})", string:version);

var short_num, short_type;
if (empty_or_null(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else
{
  short_type = short_version[1];
  short_num = short_version[2];
}

if (short_type != 'ce')
  audit(AUDIT_NOT_DETECT, app_name);

var product_info = {
  'version' : short_num
};

var vuln_ranges = [
  {'min_ver' : '9.0', 'fix_ver' : '10.19.3'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , version,
  'bug_id'        , 'CSCwc47201',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info      :product_info,
  reporting         :reporting,
  vuln_ranges       :vuln_ranges
);
