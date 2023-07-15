#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103702);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-12239");
  script_bugtraq_id(101042);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc65866");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve77132");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170927-cc");

  script_name(english:"Cisco IOS XE Line Card Console Access Vulnerability (cisco-sa-20170927-cc)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the
  Cisco IOS XE software running on the remote device is affected
  by a local privilege escalation vulnerability. An unauthenticated attacker, with
  physical access, can exploit this vulnerability to gain access to
  an affected devices' operating system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170927-cc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa432e5b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID's
  CSCvc65866 and CSCve77132.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12239");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;


ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if(model !~ 'ASR1k' && model !~ 'ASR10[0-9][0-9]' &&  model !~ 'cBR')
  audit(AUDIT_HOST_NOT, "ASR 1000 Series or cBR-8 Router");

vuln_versions = make_list(
'3.16.0S',
'3.16.1S',
'3.17.0S',
'3.17.1S',
'3.16.2S',
'3.18.0aS',
'3.18.0S',
'3.18.1S',
'3.18.0SP',
'3.18.1SP',
'3.18.1aSP',
'3.18.2SP',
'3.15.1xbS',
'3.15.2xbS',
'3.16.1aS',
'3.16.2aS',
'3.16.2bS',
'3.16.3S',
'3.16.3aS',
'3.16.4S',
'3.16.4aS',
'3.16.4bS',
'3.16.4dS',
'3.16.5S',
'3.17.2S ',
'3.17.1aS',
'3.17.3S',
'3.18.3vS',
'3.18.2S',
'3.18.3aS',
'3.18.1gSP',
'3.18.1hSP',
'3.18.1bSP',
'3.18.1cSP',
'3.16.4cS',
'3.16.4eS',
'3.16.5aS',
'3.16.5bS',
'3.16.4gS',
'2.3.0t',
'2.3.1t',
'2.3.0a',
'2.3.0b',
'2.3.0c',
'2.1.2',
'2.2.2b',
'3.4.9SG',
'3.13.0S',
'3.13.1S',
'3.13.2S',
'3.13.3S',
'3.13.4S',
'3.13.5S',
'3.13.2aS',
'3.13.0aS',
'3.13.5aS',
'3.14.0S',
'3.14.1S',
'3.14.2S',
'3.14.3S',
'3.14.4S',
'3.15.0S',
'3.15.1S',
'3.15.2S',
'3.15.1cS',
'3.15.3S',
'3.15.4S',
'3.16.0aS',
'3.16.0bS',
'3.16.0cS',
'2.7.0',
'2.8.0',
'11.3.1',
'11.3.2');

# Check for vuln version
foreach version (vuln_versions)
{
  if (version == ver)
  {
    flag++;
    break;
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    version  : ver,
    bug_id   : "CSCvc65866, CSCve77132"
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE software", ver);
