#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126625);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id("CVE-2019-9702", "CVE-2019-9703");
  script_bugtraq_id(108795, 108796);

  script_name(english:"Symantec Encryption Desktop Multiple Vulnerabilities (SYMSA1485)");
  script_summary(english:"Checks the Symantec Encryption Desktop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a data encryption application installed that is
affected by multiple privilege escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Encryption Desktop installed on the remote
host is affected by two privilege escalation vulnerabilities. A local
attacker could exploit these vulnerabilities to gain elevated access
to the system.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/0/0/symsa1485
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3f99489");
  script_set_attribute(attribute:"solution", value:
"Follow vendor guidance provided within the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9702");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pgp_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_encryption_desktop_installed.nbin", "macosx_symantec_encryption_desktop_installed.nbin");
  script_require_keys("installed_sw/Symantec Encryption Desktop", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");

var app_info, win_local;

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (get_kb_item("SMB/Registry/Enumerated")) win_local = TRUE;

app_info = vcf::get_app_info(app:"Symantec Encryption Desktop", win_local:win_local);
vcf::report_results(app_info:app_info, fix:"See Advisory", severity:SECURITY_WARNING);
