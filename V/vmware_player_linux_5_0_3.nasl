#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71052);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id("CVE-2013-5972");
  script_bugtraq_id(63739);
  script_xref(name:"VMSA", value:"2013-0013");

  script_name(english:"VMware Player 5.x < 5.0.3 Host Privilege Escalation (VMSA-2013-0013)");
  script_summary(english:"Checks VMware Player version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains software with a known, local privilege
escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of VMware Player 5.x running on Linux is earlier
than 5.0.3.  It therefore reportedly contains a vulnerability in its
handling of shared libraries.  This issue may allow a local, malicious
user to escalate privileges to root on the host."
  );
  script_set_attribute(attribute:"solution", value:"Update to VMware Player 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5972");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");
  script_family(english:"General");

  script_dependencies("vmware_player_linux_installed.nbin");
  script_exclude_keys("SMB/Registry/Enumerated");
  script_require_keys("Host/VMware Player/Version");
  exit(0);
}

include("vcf.inc");

var app = "VMware Player";
var app_info = vcf::get_app_info(app:app);

var constraints = [{'fixed_version' : '5.0.3'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

