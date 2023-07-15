#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111757);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/21");

  script_cve_id("CVE-2018-3646");
  script_bugtraq_id(105080);
  script_xref(name:"VMSA", value:"2018-0020");

  script_name(english:"VMware Workstation 14.x < 14.1.3 Speculative Execution Side Channel Vulnerability (Foreshadow) (VMSA-2018-0020) (Linux)");
  script_summary(english:"Checks the VMware Workstation version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Linux host is
affected by a speculative execution side channel vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote Linux host
is 14.x prior to 14.1.3. It is, therefore, affected by a speculative
execution side channel attack known as L1 Terminal Fault (L1TF). An
attacker who successfully exploited L1TF may be able to read
privileged data across trust boundaries.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0020.html");
  script_set_attribute(attribute:"see_also", value:"https://foreshadowattack.eu/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Workstation version 14.1.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3646");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version", "Settings/ParanoidReport");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_OS_NOT, "Linux", "Windows");

version = get_kb_item_or_exit("Host/VMware Workstation/Version");

fix = '';
if (version =~ "^14\.") fix = '14.1.3';

if (!empty(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware Workstation", version);
