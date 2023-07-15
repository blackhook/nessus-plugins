#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109730);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2018-10115");
  script_bugtraq_id(104132);
  script_xref(name:"IAVA", value:"2018-A-0147-S");

  script_name(english:"7-Zip < 18.05 Memory Corruption Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"A compression utility installed on the remote Windows host is affected
by arbitrary code execution.");
  script_set_attribute(attribute:"description", value:
"The version of 7-Zip installed on the remote Windows host contains a
flaw in the NArchive::NRar::CHandler::Extract method in 
Archive/Rar/RarHandler.cpp. The issue is triggered as certain input 
is not properly validated when performing 'solid' decompression of a
RAR archive. With a specially crafted file, a context-dependent 
attacker can corrupt memory to cause a denial of service or 
potentially execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://www.7-zip.org/history.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.neowin.net/news/peazip-660");
  # https://nvd.nist.gov/vuln/detail/CVE-2018-10115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2f13c3c");
  # https://landave.io/2018/05/7-zip-from-uninitialized-memory-to-remote-code-execution/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95f517fd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7-Zip version 18.05 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10115");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("7zip_installed.nbin");
  script_require_keys("installed_sw/7-Zip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = '7-Zip';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

fix = "18.05";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version);
