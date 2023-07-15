#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 05/19/2020. Temporarly disabled to address detection issues.

include('compat.inc');

if (description)
{
  script_id(134163);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/19");

  script_cve_id("CVE-2020-3943", "CVE-2020-3944", "CVE-2020-3945");
  script_xref(name:"VMSA", value:"2020-0003");
  script_xref(name:"IAVB", value:"2020-B-0009");

  script_name(english:"VMware vRealize Operations for Horizon Adapter Multiple Vulnerabilities (VMSA-2020-0003) (disabled)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been disabled.");
  script_set_attribute(attribute:"description", value:
"Due to a deteciton issue this plugin has been temporarily disabled.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0003.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3943");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations_horizon_desktop_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_operations_horizon_desktop_agent_installed.nbin");
  script_require_ports("installed_sw/VMware vRealize Operations for Horizon Desktop Agent");

  exit(0);
}

exit(0, "This plugin has been temporarily disabled.");
