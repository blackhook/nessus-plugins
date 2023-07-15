#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72039);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2014-1208");
  script_bugtraq_id(64994);
  script_xref(name:"VMSA", value:"2014-0001");

  script_name(english:"VMware Player 5.x < 5.0.1 VMX Process DoS (VMSA-2014-0001) (Linux)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of VMware Player 5.x running on the remote Linux
host is a version prior to 5.0.1.  It is, therefore, affected by a
denial of service vulnerability due to an issue with handling invalid
ports that could allow a guest user to crash the VMX process.");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Player 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1208");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");

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

var constraints = [{'fixed_version' : '5.0.1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);

