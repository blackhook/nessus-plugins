#TRUSTED 87ff5c15fa3ea61748b90602d79264ec3b1ef676ba1b7c3a375f068a57efdc172cf0256391b7b170068acb1ab5d83096963fbfb25c7698942fe531ad67eeec1a33a6bda73a26567cc53503a937f6855b29ea9250335d2626ab8075078ea9b77618e9810102e6eb141d947b664bb8139968e7ad0e0833b618d352b231375e784d7f01781fbbbf8d19c590c011b2fc585f77c795f4b65fc97bf9838cd19766c743ed1cfe57f1b2ffa5f151afe665c3d2ae83205db671d8f2cd006501193fe102a295dd49a9386f8f1e97a18f557a19fbcdad6179ceebae28c23c5498eef50c81856005ba85ba6b3d72a836ddc5119a652b40fbb10f4e501c5db12ae8ee717043d77d74804bf6e8040c87d7649bf8be445aee865090b097f535c9754be053de232200643724e6e7c09f31e9d13dbaa7aabad6f7eeb1c29aaf63de76ddf2a75327be49d322c8d3b3b16b43098b6ab12a651a799d4348f61f2e7d5a6e5b5544c56ef1f821b726109d8bf5c50e402359bb0897d35b675d54cb7b3c5410aac94a61f6dd644121ce8ad3ebe90be71b76b139404108781d95657e620ebacdb0dc903293bc99118113132670b749b6ac39da5a46bfe10e3141e807b4c94bec973fecc50fd96b090942a12f93f7dc1e27a35e658a37f72484e7d4d328b0db249fed32d43be38ec910c1a96aef1668aa2985ad529c27af9c86ccfca574161fa186dac6182027
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160289);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2022-20783");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz55702");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ce-roomos-dos-c65x2Qf2");
  script_xref(name:"IAVA", value:"2022-A-0177-S");

  script_name(english:"Cisco TelePresence Collaboration Endpoint Software H.323 DoS (cisco-sa-ce-roomos-dos-c65x2Qf2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Collaboration Endpoint Software is affected by a
vulnerability in the packet processing functionality that could allow an unauthenticated, remote attacker to cause a
denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient input validation. An
attacker could exploit this vulnerability by sending crafted H.323 traffic to an affected device. A successful exploit
could allow the attacker to cause the affected device to either reboot normally or reboot into maintenance mode, which
could result in a DoS condition on the device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ce-roomos-dos-c65x2Qf2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70b98f3d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz55702");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz55702");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20783");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_collaboration_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var app_name = 'Cisco TelePresence CE software';
var version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');
var device = get_kb_item_or_exit('Cisco/TelePresence_MCU/Device');
device = tolower(device);

if ('telepresence' >!< device)
  audit(AUDIT_HOST_NOT, 'a vulnerable device');

# not checking for H.323
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

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
  {'min_ver' : '0.0', 'fix_ver' : '9.15.10.8'},
  {'min_ver' : '10.0', 'fix_ver' : '10.11.2.2'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , version,
  'bug_id'        , 'CSCvz55702',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info      :product_info,
  reporting         :reporting,
  vuln_ranges       :vuln_ranges
);

