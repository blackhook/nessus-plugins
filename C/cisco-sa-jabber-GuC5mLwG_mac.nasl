#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150862);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2021-1570");
  script_xref(name:"CISCO-SA", value:"cisco-sa-jabber-GuC5mLwG");
  script_xref(name:"IAVA", value:"2021-A-0291-S");

  script_name(english:"Cisco Jabber for Mac < 14.0.1 DoS (cisco-sa-jabber-GuC5mLwG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Jabber for Mac is affected by a Denial of Service vulnerability.
 This vulnerability is due to improper validation of message content. An attacker could exploit this vulnerability
 by sending crafted XMPP messages to an affected system. A successful exploit could allow the attacker to cause 
 the application to terminate, resulting in a DoS condition.

Please see the included Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-jabber-GuC5mLwG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab01e1dd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the relevant Cisco Security Advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1570");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_cisco_jabber_for_mac_installed.nbin");
  script_require_ports("installed_sw/Cisco Jabber");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Jabber');

var constraints = [
    { 'fixed_version' : '14.0.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
