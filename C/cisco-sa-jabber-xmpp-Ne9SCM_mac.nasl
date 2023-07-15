#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165759);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2022-20917");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc24382");
  script_xref(name:"CISCO-SA", value:"cisco-sa-jabber-xmpp-Ne9SCM");
  script_xref(name:"IAVA", value:"2022-A-0400");

  script_name(english:"Cisco Jabber Client For MacOS XMPP Stanza Smuggling (cisco-sa-jabber-xmpp-Ne9SCM)");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Jabber for MacOS is affected by a stanza smuggling vulnerability due
to improper handling of nested XMPP requests. An authenticated, remote attacker can send specially crafted XMPP
messages to an affected client causing the client to perform unsafe actions.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-jabber-xmpp-Ne9SCM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1a55c89");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc24382");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc24382");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20917");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(668);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_cisco_jabber_for_mac_installed.nbin");
  script_require_ports("installed_sw/Cisco Jabber");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco Jabber');

var constraints = [
    { 'fixed_version' : '12.8.8' },
    { 'min_version' : '12.9', 'fixed_version' : '12.9.8' },
    { 'min_version' : '14.0', 'fixed_version' : '14.0.5' },
    { 'min_version' : '14.1', 'fixed_version' : '14.1.3' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
