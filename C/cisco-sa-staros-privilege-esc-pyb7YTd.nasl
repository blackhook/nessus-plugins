##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141356);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/19");

  script_cve_id("CVE-2020-3602");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv34222");
  script_xref(name:"CISCO-SA", value:"cisco-sa-staros-privilege-esc-pyb7YTd");
  script_xref(name:"IAVA", value:"2020-A-0451");

  script_name(english:"Cisco StarOS Privilege Escalation (cisco-sa-staros-privilege-esc-pyb7YTd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco StarOS operating system on the remote Cisco ASR 5000 series router
is affected by a privilege escalation vulnerability due to insufficient validation of CLI commands. An authenticated,
local attacker can exploit this, by sending crafted commands to the CLI, in order to execute arbitrary code with the
privileges of the root user on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-staros-privilege-esc-pyb7YTd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1689477b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv34222");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv34222");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3602");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_5000_series");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASR/Model", "Host/Cisco/StarOS", "Host/Cisco/StarOS/Version");

  exit(0);
}

include('cisco_func.inc');

get_kb_item_or_exit('Host/Cisco/StarOS');

version = get_kb_item_or_exit('Host/Cisco/StarOS/Version');
model = get_kb_item_or_exit('Host/Cisco/ASR/Model');

# only affects ASR 5000 series systems
if (model !~ "^50\d{2}$")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ASR ' + model);

# Normalize characters
upper_version = toupper(version);

fix_major = '21.19';
vuln = FALSE;

major = pregmatch(pattern:"^([0-9]+\.[0-9]+)", string:version);
if (!empty_or_null(major))
    major = major[1];
else
  exit(1, "Unable to extract version number.");

# Vuln if major < 21.19
if (ver_compare(strict:FALSE, ver:major, fix:fix_major) < 0)
  vuln = TRUE;

# Vuln if major is 21.19 and train < N4, based on the order here
# https://software.cisco.com/download/home/286318274/type/286319061/os/Linux/release/21.19.n4 it looks like 21.19.n4 is
# > 20.19.4 and < 21.19.5
# 21.19 will only be the new style version with no parens
if (upper_version =~ "21\.19\.[A-Z]{0,2}[0-3]([^0-9]|$)" || upper_version =~ "21\.19\.4([^0-9]|$)")
  vuln = TRUE;

if (!vuln)
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco StarOS', version);

security_report_cisco(
  port     : 0,
  severity : SECURITY_HOLE,
  version  : version,
  fix      : '21.19.n4',
  bug_id   : 'CSCvv34222'
);
