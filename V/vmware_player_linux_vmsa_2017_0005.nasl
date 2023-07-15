#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97989);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2017-4901");
  script_bugtraq_id(96881);
  script_xref(name:"VMSA", value:"2017-0005");

  script_name(english:"VMware Player 12.x < 12.5.4 Drag-and-Drop Feature Guest-to-Host Code Execution (VMSA-2017-0005) (Linux)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Linux host is
affected by a guest-to-host arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote Linux host
is 12.x prior to 12.5.4. It is, therefore, affected by a guest-to-host
arbitrary code execution vulnerability in the drag-and-drop (DND)
functionality due to an out-of-bounds memory access error. An attacker
within a guest can exploit this issue to execute arbitrary code on the
host system.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0005.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player version 12.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-4901");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_player_linux_installed.nbin");
  script_require_keys("Host/VMware Player/Version");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

var app = "VMware Player";
var app_info = vcf::get_app_info(app:app);

var constraints = [{'fixed_version' : '12.5.4'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

