#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136670);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/02");

  script_cve_id("CVE-2020-0557", "CVE-2020-0558", "CVE-2020-0569");
  script_xref(name:"IAVA", value:"2020-A-0209");

  script_name(english:"Intel® PROSet/Wireless WiFi Software x < 21.70.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The Intel wireless network adapter driver installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A wireless network adapter driver on the remote host is affected by multiple
security vulnerabilities:
 
 - Insecure inherited permissions in Intel(R) PROSet/Wireless WiFi products
   before version 21.70 on Windows 10 may allow an authenticated user to
   potentially enable escalation of privilege via local access. (CVE-2020-0557)
 
 - Improper buffer restrictions in kernel mode driver for Intel(R)
   PROSet/Wireless WiFi products before version 21.70 on Windows 10 may allow
   an unprivileged user to potentially enable denial of service via adjacent
   access. (CVE-2020-0558)

 - Out of bounds write in Intel(R) PROSet/Wireless WiFi products on Windows
   10 may allow an authenticated user to potentially enable denial of service via
   local access. (CVE-2020-0569)
 
 Note that Nessus has not tested for this issue but has instead relied only
 on the application's self-reported version number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00338.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df6d6c81");
  script_set_attribute(attribute:"solution", value:
"Update your network adapter software as per the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0557");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:proset\/wireless_wifi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_enum_network_adapters.nasl");
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('lists.inc');
include('smb_hotfixes.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

adapters = get_kb_list('SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/Class/{4d36e972-e325-11ce-bfc1-08002be10318}/*/DriverDesc');

if (max_index(keys(adapters)) == 0)
  audit(AUDIT_HOST_NOT, 'affected');

report = '';
foreach desc_kb (keys(adapters))
{
  desc = get_kb_item(desc_kb);
  version_kb = desc_kb - '/DriverDesc' + '/DriverVersion';
  instanceid_kb = desc_kb - '/DriverDesc' + '/DeviceInstanceID'; 
  version = get_kb_item(version_kb);
  instanceid = get_kb_item(instanceid_kb); 
  fixed = NULL;
  fixedpkg = '21.70.0';

  # Intel® Wi-Fi 6 AX201
  # Intel® Wi-Fi 6 AX200
  # Intel® Wireless-AC 9560
  # Intel® Wireless-AC 9462
  # Intel® Wireless-AC 9461
  # Intel® Wireless-AC 9260
  # x < 21.70.0.6
  if (collib::contains(['Intel(R) Wi-Fi 6 AX201', 'Intel(R) Wi-Fi 6 AX200', 'Intel(R) Wireless-AC 9560', 'Intel(R) Wireless-AC 9462', 'Intel(R) Wireless-AC 9461', 'Intel(R) Wireless-AC 9260'], desc))
  {
    fixed = '21.70.0.6';
  }
  # Intel® Dual Band Wireless-AC 8265
  # Intel® Dual Band Wireless-AC 8260
  # x < 20.70.16.4
  else if (collib::contains(['Intel(R) Dual Band Wireless-AC 8265', 'Intel(R) Dual Band Wireless-AC 8260'], desc))
  {
    fixed = '20.70.16.4';
  }
  # Intel® Dual Band Wireless-AC 3168
  # Intel® Dual Band Wireless-AC 3165
  # x < 19.51.27.1
  else if (collib::contains(['Intel(R) Dual Band Wireless-AC 3168', 'Intel(R) Dual Band Wireless-AC 3165'], desc))
  {
    fixed = '19.51.27.1';
  }
  # Intel® Wireless 7265 (Rev D) Family
  #   Intel® Dual Band Wireless-AC 7265
  #   Intel® Dual Band Wireless-N 7265
  #   Intel® Wireless-N 7265
  # x < 19.51.27.1
  # REV_3B, REV_43, REV_48, REV_50 are Rev C. All others are Rev D:
  # https://www.intel.com/content/www/us/en/support/articles/000026395/network-and-i-o/wireless-networking.html
  else if (collib::contains(['Intel(R) Dual Band Wireless-AC 7265', 'Intel(R) Dual Band Wireless-N 7265', 'Intel(R) Wireless-N 7265'], desc)
           && instanceid !~ "(?i)[^0-9a-z](REV_3B|REV_43|REV_48|REV_50)[^0-9a-z]")
  {
    fixed = '19.51.27.1';
  }

  if (!isnull(fixed) && ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
  {
    report += 'Fixed Software Package                   : ' + fixedpkg + '\n';
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

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
