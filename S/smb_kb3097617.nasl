#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87875);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_xref(name:"IAVB", value:"2016-B-0018-S");
  script_xref(name:"MSKB", value:"3123479");

  script_name(english:"MS KB3123479: Deprecation of SHA-1 Hashing Algorithm for Microsoft Root Certificate Program");
  script_summary(english:"Checks the registry.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing an update that improves
cryptography and digital certificate handling.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing Microsoft KB3123479, an update that
restricts the use of certificates with SHA1 hashes, this restriction
being limited to certificates issued under roots in the Microsoft root
certificate program. This update increases the difficulty of carrying
out some spoofing, phishing, and man-in-the-middle attacks.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2017/3123479
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?475a7f5b");
  # https://social.technet.microsoft.com/wiki/contents/articles/32288.windows-enforcement-of-sha1-certificates.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22c2e18d");
  # https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/ms537628(v=vs.85)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9a90a63");
  # https://support.microsoft.com/en-us/help/3097617/cumulative-update-for-windows-10-october-13-2015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7a673f6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 2008 R2, 8,
2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available. Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("byte_func.inc");

port = kb_smb_transport();
os = get_kb_item_or_exit('SMB/WindowsVersion');

# Windows Embedded is not supported by Nessus
# There are cases where this plugin is flagging embedded
# hosts improperly since this update does not apply
# to those machines
productname = get_kb_item("SMB/ProductName");
if ("Embedded" >< productname)
  exit(0, "Nessus does not support bulletin / patch checks for Windows Embedded.");

if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

os_build = get_kb_item("SMB/WindowsVersionBuild");

# Audit out if win10 build > 1607
if ("10" >< os && !("10240" == os_build || "10586" == os_build || "14393" == os_build)) audit(AUDIT_HOST_NOT, "affected");

# November 2016 rollup removed the registry keys and will cause false positives
# Simply check if 11_2016 rollup or later was detected
rollup_date = "11_2016";
if (get_kb_item("smb_rollup/" + rollup_date))
  audit(AUDIT_HOST_NOT, 'affected');

host_rollup = get_kb_item('smb_rollup/latest');  
if (!isnull(host_rollup))
{
  host_rollup = split(host_rollup, sep:'_');
  h_month = int(host_rollup[0]);
  h_year = int(host_rollup[1]);

  new_rollup = split(rollup_date, sep:'_');
  n_month = int(new_rollup[0]);
  n_year = int(new_rollup[1]);

  # Determine if host rollup >= supplied rollup
  if (h_year > n_year || (h_year == n_year && h_month >= n_month))
    audit(AUDIT_HOST_NOT, 'affected');    
}

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
names = make_list(
  'WeakSha1ThirdPartyFlags',
  'WeakSha1ThirdPartyAfterTime'
);
key = "Software\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config\default";
values = get_values_from_key(handle:hklm, entries:names, key:key);
RegCloseKey(handle:hklm);
close_registry();

flags = values['WeakSha1ThirdPartyFlags'];
time = values['WeakSha1ThirdPartyAfterTime'];
key = "HKEY_LOCAL_MACHINE\" + key;

# if none of the data created by KB3123479 is present, it probably hasn't been installed
if (isnull(flags) && isnull(time))
{
  if (report_verbosity > 0)
  {
    report =
      '\nIt appears KB3123479 has not been installed since the following' +
      '\nregistry key does not exist and/or does not contain any of the following values :\n\n' +
      key + '\n\n' +
      join(names, sep:'\n') + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}

# if the data is present, make sure it matches up with what is expected from KB2862973
expected_time = '0018df076244d101';
if (hexstr(time) != expected_time)
{
  if (report_verbosity > 0)
  {
    report =
      '\nIt appears KB3123479 has not been installed since the following' +
      '\nregistry value does not exist and/or does not contain the expected data :\n\n' +
      'Key            : ' + key + '\n' +
      'Name           : WeakSha1ThirdPartyAfterTime\n' +
      'Expected value : ' + expected_time + '\n';
    if (isnull(time))
      report += 'Actual value   : (does not exist)\n';
    else
      report += 'Actual value   : ' + hexstr(time) + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}

expected_flags = uint(0x80800000);
if ((flags & expected_flags) != expected_flags)
{
  if (report_verbosity > 0)
  {
    report =
      '\nIt appears KB3123479 has not been installed since the following' +
      '\nregistry value does not exist and/or does not contain the expected data :\n\n' +
      'Key            : ' + key + '\n' +
      'Name           : WeakSha1ThirdPartyFlags\n' +
      'Expected value : ' + expected_flags + ' (0x80800000)\n';
    if (isnull(time))
      report += 'Actual value   : (does not exist)\n';
    else
      report += 'Actual value   : ' + flags + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}

audit(AUDIT_HOST_NOT, 'affected');
