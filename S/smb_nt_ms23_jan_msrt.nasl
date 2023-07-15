#%NASL_MIN_LEVEL 80900
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(169783);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2023-21725");

  script_name(english:"Security Updates for Windows Malicious Software Removal Tool (January 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antimalware application that is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows Malicious Software Removal Tool installation on
  the remote host is missing a security update. It is, therefore,
  affected by the following vulnerability:
  
    - An elevation of privilege vulnerability. An attacker can
      exploit this to gain elevated privileges.
      (CVE-2023-21725)");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21725
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?867b0b4e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released version 5.109 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:malware_protection_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_mrt_installed.nasl");
  script_require_keys("SMB/MRT/Version");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');

var version = get_kb_item_or_exit('SMB/MRT/Version');
var app = 'Microsoft Malicious Software Removal Tool';

var port, report;
if (ver_compare(ver:version, fix:'5.109.19957.1') == -1)
{
  port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : Microsoft Malicious Software Removal Tool' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.109.19957.1\n';
    security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  }
  else security_report_v4(port:port, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
