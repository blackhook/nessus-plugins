#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103529);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id("CVE-2017-3897", "CVE-2017-3898");
  script_xref(name:"IAVB", value:"2017-B-0130");

  script_name(english:"McAfee Security Scan Plus < 3.11.599.3 LiveSafe Non-certificate-based Authentication HTTP Backend-response Handling MitM Registry Value Manipulation (TS102723)");
  script_summary(english:"Checks the version of McAfee Security Scan Plus.");

  script_set_attribute(attribute:"synopsis", value:
"The security application installed on the remote Windows host is
affected by a MitM command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Security Scan Plus installed on the remote
Windows host is prior to 3.11.599.3. It is, therefore, affected by
a flaw in the non-certificate-based authentication mechanism that is
triggered during the handling of HTTP backend-responses. This may
allow a man-in-the-middle attacker to make changes to the Windows
registry value associated with the McAfee update.");
  # https://service.mcafee.com/webcenter/portal/oracle/webcenter/page/scopedMD/s55728c97_466d_4ddb_952d_05484ea932c6/Page29.jspx?wc.contextURL=%2Fspaces%2Fcp&articleId=TS102723&leftWidth=0%25&showFooter=false&showHeader=false&rightWidth=0%25&centerWidth=100%25
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e56e2027");
  # https://blogs.securiteam.com/index.php/archives/3248
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32b323c1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Security Scan Plus version 3.11.599.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:security_scan_plus");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("mcafee_ssp_installed.nbin");
  script_require_keys("installed_sw/McAfee Security Scan Plus");
  script_require_ports(139, 445);

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"McAfee Security Scan Plus", win_local:TRUE);

constraints = [{ "fixed_version" : "3.11.599.3" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
