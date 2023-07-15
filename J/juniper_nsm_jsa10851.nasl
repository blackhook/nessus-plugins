#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109406);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2017-3735",
    "CVE-2017-3736",
    "CVE-2017-3737",
    "CVE-2017-3738"
  );
  script_bugtraq_id(
    100515,
    101666,
    102103,
    102118
  );
  script_xref(name:"IAVA", value:"2018-A-0134");

  script_name(english:"Juniper NSM < 2012.2R14 OpenSSL Multiple Vulnerabilities (JSA10851)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of NSM (Network and Security
Manager) Server that is prior to 2012.2R14. It is, therefore, affected
by multiple vulnerabilities in the bundled version of OpenSSL.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10851");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper NSM version 2012.2R14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:network_and_security_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "juniper_nsm_gui_svr_detect.nasl");
  script_require_keys("Juniper_NSM_VerDetected", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

kb_base = "Host/NSM/";

# Since we can't detect the package change remotely this needs to be paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Juniper_NSM_VerDetected");

kb_list = make_list();

temp = get_kb_list("Juniper_NSM_GuiSvr/*/build");

if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

temp = get_kb_list("Host/NSM/*/build");
if (!isnull(temp) && max_index(keys(temp)) > 0)
  kb_list = make_list(kb_list, keys(temp));

if (max_index(kb_list) == 0) audit(AUDIT_NOT_INST, "Juniper NSM Servers");

report = '';

entry = branch(kb_list);

port = 0;
kb_base = '';

if ("Juniper_NSM_GuiSvr" >< entry)
{
  port = entry - "Juniper_NSM_GuiSvr/" - "/build";
  kb_base = "Juniper_NSM_GuiSvr/" + port + "/";

  report_str1 = "Remote GUI server version : ";
  report_str2 = "Fixed version             : ";
}
else
{
  kb_base = entry - "build";
  if ("guiSvr" >< kb_base)
  {
    report_str1 = "Local GUI server version : ";
    report_str2 = "Fixed version            : ";
  }
  else
  {
    report_str1 = "Local device server version : ";
    report_str2 = "Fixed version               : ";
  }
}

build = get_kb_item_or_exit(entry);
version = get_kb_item_or_exit(kb_base + 'version');

version_disp = version + " (" + build + ")";

# NSM 2012.2R14 or later
# replace r or R with . for easier version comparison
# in 2010 and 2011 versions they use S instead of R
version_num = ereg_replace(pattern:"(r|R|s|S)", replace:".", string:version);

# remove trailing . if it exists
version_num = ereg_replace(pattern:"\.$", replace:"", string:version_num);

fix_disp = "2012.2R14";
fix_num = "2012.2.14";
if (ver_compare(ver:version_num, fix:fix_num, strict:FALSE) < 0)
{
  report = '\n  ' + report_str1 + version_disp +
           '\n  ' + report_str2 + fix_disp +
           '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Juniper NSM", version_disp);
