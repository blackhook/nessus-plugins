#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74264);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2014-3793");
  script_bugtraq_id(67737);
  script_xref(name:"VMSA", value:"2014-0005");

  script_name(english:"VMware Player 6.x < 6.0.2 Windows 8.1 Guest Privilege Escalation (VMSA-2014-0005) (Linux)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains software that is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of VMware Player 6.x running on the remote Linux
host is prior to 6.0.2. It is, therefore, reportedly affected by a
privilege escalation vulnerability.

A kernel NULL dereference flaw exists in VMware tools on Windows 8.1
guest hosts. An attacker could escalate his privileges on the guest
host.

Note that successful exploitation of the vulnerability does not allow
privilege escalation from the guest host to the host system.");
  # https://www.vmware.com/support/player60/doc/player-602-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7df547df");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Player 6.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_player_linux_installed.nbin");
  script_require_keys("Host/VMware Player/Version");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

var app = "VMware Player";
var app_info = vcf::get_app_info(app:app);

var constraints = [{'fixed_version' : '6.0.2'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

