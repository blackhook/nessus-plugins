#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103870);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/29");

  script_cve_id("CVE-2017-13080", "CVE-2017-13081");
  script_bugtraq_id(101274);
  script_xref(name:"CERT", value:"228519");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"Intel Wireless Driver Wi-Fi Protected Access II (WPA2) Multiple Vulnerabilities (KRACK)");

  script_set_attribute(attribute:"synopsis", value:
"A wireless network adapter driver on the remote host is affected by multiple protocol vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Intel wireless network adapter driver installed on the remote host is affected by multiple vulnerabilities in the
WPA2 protocol.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00101.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bb24c68");
  script_set_attribute(attribute:"see_also", value:"https://www.krackattacks.com/");
  script_set_attribute(attribute:"solution", value:"Update your network adapter driver as per the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13080");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:dual_band_wireless-ac_3160");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:dual_band_wireless-ac_3160");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:dual_band_wireless-ac_3165");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:dual_band_wireless-ac_3165");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:dual_band_wireless-ac_3168");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:dual_band_wireless-ac_3168");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:dual_band_wireless-ac_7260");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:dual_band_wireless-ac_7260");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:dual_band_wireless-ac_7265");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:dual_band_wireless-ac_7265");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:dual_band_wireless-ac_8260");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:dual_band_wireless-ac_8260");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:dual_band_wireless-ac_8265");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:dual_band_wireless-ac_8265");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:dual_band_wireless-ac_9260");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:dual_band_wireless-ac_9260");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_network_adapters.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

adapters = get_kb_list('SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/Class/{4d36e972-e325-11ce-bfc1-08002be10318}/*/DriverDesc');

if (max_index(keys(adapters)) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

report = '';
foreach desc_kb (keys(adapters))
{
  desc = get_kb_item(desc_kb);
  version_kb = desc_kb - '/DriverDesc' + '/DriverVersion';
  version = get_kb_item(version_kb);
  fixed = NULL;

  # Intel(r) Dual Band Wireless-AC 3160 18.x.x.x < 18.33.9.3
  if (desc == 'Intel(R) Dual Band Wireless-AC 3160')
  {
    if (version =~ "^18\.")
      fixed = "18.33.9.3";
  }
  # Intel(r) Dual Band Wireless-AC 3165 19.10.x.x < 19.10.9.2, 19.51.x.x < 19.51.7.2
  else if (desc == 'Intel(R) Dual Band Wireless-AC 3165')
  {
    if (version =~ "^19\.10\.")
      fixed = '19.10.9.2';
    else if (version =~ "^19\.51\.")
      fixed = '19.51.7.2';
  }
  # Intel(r) Dual Band Wireless-AC 3168 19.10.x.x < 19.10.9.2, 19.51.x.x < 19.51.7.2
  else if (desc == 'Intel(R) Dual Band Wireless-AC 3168')
  {
    if (version =~ "^19\.10\.")
      fixed = '19.10.9.2';
    else if (version =~ "^19\.51\.")
      fixed = '19.51.7.2';
  }
  # Intel(r) Dual Band Wireless-AC 7260 18.x.x.x < 18.33.9.3
  else if (desc == 'Intel(R) Dual Band Wireless-AC 7260')
  {
    if (version =~ "^18\.")
      fixed = '18.33.9.3';
  }
  # Intel(r) Dual Band Wireless-AC 7265 19.10.x.x < 19.10.9.2, 19.51.x.x < 19.51.7.2
  else if (desc == 'Intel(R) Dual Band Wireless-AC 7265')
  {
    if (version =~ "^19\.10\.")
      fixed = '19.10.9.2';
    else if (version =~ "^19\.51\.")
      fixed = '19.51.7.2';
  }
  # Intel(r) Dual Band Wireless-AC 8260/8265/9260 20.x.x.x < 20.0.2.3
  else if (desc =~ "^Intel\(R\) Dual Band Wireless-AC (8260|8265|9260)$")
  {
    if (version =~ "^20\.")
      fixed = '20.0.2.3';
  }

  if (!isnull(fixed) && ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
  {
    report += 'Network Adapter Driver Description       : ' + desc + '\n';
    report += 'Network Adapter Driver Installed Version : ' + version + '\n';
    report += 'Network Adapter Driver Fixed Version     : ' + fixed + '\n';
    report += '\n';
  }
}

if (empty_or_null(report))
  audit(AUDIT_HOST_NOT, 'affected');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
