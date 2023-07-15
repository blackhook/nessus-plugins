#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105154);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/23  7:32:57");

  script_cve_id("CVE-2016-2563");
  script_bugtraq_id(84296);

  script_name(english:"PuTTY < 0.67 PSCP Server Header Handling Stack Buffer Overflow");
  script_summary(english:"Checks the version of PuTTY.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of PuTTY installed that is prior to
0.67. It is, therefore, affected by a stack-based buffer overflow
related to handling SCP-SINK file-size responses that could allow
arbitrary code execution.");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-pscp-sink-sscanf.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d98e5112");
  script_set_attribute(attribute:"see_also", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to PuTTY version 0.67 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2563");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("putty_installed.nasl");
  script_require_keys("installed_sw/PuTTY", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"PuTTY", win_local:TRUE);

constraints = [
  { "fixed_version" : "0.67" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
