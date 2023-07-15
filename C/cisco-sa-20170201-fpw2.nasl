#TRUSTED ab9300e783b5b0deca66796369fbe293f083af6894e5923d8ef310940e4dde7c81780576ed20b308c1122a6a4ae5ce680aeaf71cf9bc4c6287f1c218bebfaa9a0422a1e6370e5e9e8147423a2ea960c020de69bd11b17f5c133d7da36d33069967de146463a9dcc1ed3c5abe2f1a18068d63f3429eb91d8ca868c9c4c6d9a6f0971a1328a3fadf45725c08421afff95d419fd6f7ff6fd4f0cefe388d84d6c7eb03a48f421336749976e07c97cf2ae1c9e425bbe8ff44074a58b1785d6599bad99cdcc50cb1d425de651a8c8ac255c55b80cf1314a3b9419c1ff3a5c801ed480086bbf2bb34432832a672d625c8263d2cbdbc448b6a19253852d2b84e30cd31d24d3c82bb23b2b19bb7172863fc8e72e5575a00497d2a9f9118166b0ae6910d1890626205593aaf435339171aded375b655bd0629c07934a3788f653d2ec7782955cf88311a617267e4a9640b56079aa961e315e73e17627d05e9f92865f11655a96f04ee4f0fb84ed2ffe10535d2475c47b3581f2a0f9c4d06123a923c52ecbd42799460a72cb877dda8702bc824eb8d794030e161975bde51e25424367bd8b54de73e4d0048889c1f80d0eb836840e6e631a948a475768a08e75459cca5f41b27296e94f8c9a7ec36b3c0c9b57aafb526056ad739bd7240f5a4de09f3af94aa9cd79f1fb06541cd8062a6242b2b6fc580b4390d5ec8bf659a11a9c98e6c7b25
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99400);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3822");
  script_bugtraq_id(95944);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb86860");
  script_xref(name:"IAVB", value:"2017-B-0019");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170201-fpw2");

  script_name(english:"Cisco Firepower Threat Defense Device Manager Web UI Request Handling Arbitrary Log Entry Injection (cisco-sa-20170201-fpw2)");
  script_summary(english:"Checks the version of Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by an arbitrary log entry injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Firepower Threat
Defense (FTD) software installed on the remote device is affected by
an arbitrary log entry injection vulnerability in the Firepower Device
Manager (FDM) due to improper validation of user-supplied input. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request to the web UI, to add arbitrary entires and false
alarms to the audit log.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170201-fpw2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8709094");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb86860.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");
include("obj.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

# Affected Models:
# 5506-X
# 5506W-X
# 5506H-X
# 5508-X
# 5512-X
# 5515-X
# 5516-X
# 5525-X
# 5545-X
# 5555-X
if (
  model !~ '^5506[WH]?-X' &&
  model !~ '^5508-X' &&
  model !~ '^551[256]-X' &&
  model !~ '^5525-X' &&
  model !~ '^5545-X' &&
  model !~ '^5555-X'
) audit(AUDIT_HOST_NOT, "an affect Cisco ASA product model");

flag = 0;
override = 0;

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(fdm_ver)) audit(AUDIT_HOST_NOT, "affected");

if (fdm_ver[1] =~ "^6\.1\.")
  flag= 1;

cmds = make_list();
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_managers", "show managers");
    if (check_cisco_result(buf))
    {
      # Vulnerable if managed locally
      if (preg(pattern:"^\s*Managed locally", multiline:TRUE, string:buf))
      {
        flag = 1;
        cmds = make_list(cmds, "show managers");
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : fdm_ver[1],
    bug_id   : "CSCvb86860",
    cmds     : cmds
  );
} else audit(AUDIT_HOST_NOT, "affected");
