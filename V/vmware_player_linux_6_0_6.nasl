#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84221);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2015-2341");
  script_bugtraq_id(75094);
  script_xref(name:"VMSA", value:"2015-0004");

  script_name(english:"VMware Player 6.x < 6.0.6 RPC Command DoS (VMSA-2015-0004) (Linux)");
  script_summary(english:"Checks the VMware Player version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Player installed on the remote Linux host is 6.x
prior to 6.0.6. It is, therefore, affected by a denial of service
vulnerability due to improper validation of user-supplied input to a
remote procedure call (RPC) command. An unauthenticated, remote
attacker can exploit this, via a crafted command, to crash the host or
guest operating systems.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Player version 6.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2341");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("vmware_player_linux_installed.nbin");
  script_require_keys("Host/uname", "Host/VMware Player/Version");
  exit(0);
}

include("vcf.inc");

var app = "VMware Player";
var app_info = vcf::get_app_info(app:app);

var constraints = [{'fixed_version' : '6.0.6'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

