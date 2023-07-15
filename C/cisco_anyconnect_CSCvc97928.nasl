#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100790);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-6638");
  script_bugtraq_id(98938);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170607-anyconnect");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc97928");

  script_name(english:"Cisco AnyConnect Secure Mobility Client < 4.4.02034 Local Privilege Escalation");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"A VPN application installed on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco AnyConnect Secure Mobility Client installed on
the remote Windows host is prior to 4.4.02034. It is, therefore,
affected by a local privilege escalation vulnerability due to improper
validation of paths and filenames of dynamic-link library (DLL) files
before they are loaded. A local attacker can exploit this, via a
specially crafted DLL file, to escalate privileges and execute
commands with SYSTEM level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-anyconnect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b76d8a8e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc97928");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version 4.4.02034
or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6638");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Cisco AnyConnect Secure Mobility Client", win_local:TRUE);

constraints = [{ "fixed_version" : "4.4.2034.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
