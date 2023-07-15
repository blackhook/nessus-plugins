#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102431);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5807", "CVE-2017-5808", "CVE-2017-5809");
  script_xref(name:"HP", value:"emr_na-hpesbgn03732");
  script_xref(name:"HP", value:"HPESBGN03732");
  script_xref(name:"IAVA", value:"2017-A-0243");

  script_name(english:"HP Data Protector 8.x < 8.17 / 9.x < 9.09 Multiple Vulnerabilities (HPSBGN03732)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Data Protector installed on the remote host is
8.x prior to 8.17, or 9.x prior to 9.09. It
is, therefore, affected by the following vulnerabilities :

  - HPE Data Protector contains an unspecified overflow 
    condition that is triggered as certain input is not 
    properly validated. This may allow a remote attacker 
    to cause a stack-based buffer overflow, resulting in 
    a denial of service or potentially allowing the 
    execution of arbitrary code. (CVE-2017-5807)

  - HPE Data Protector contains an unspecified flaw that 
    may allow a remote attacker to cause a denial of 
    service. No further details have been provided by 
    the vendor. (CVE-2017-5808)
  
  - HPE Data Protector contains an unspecified flaw related 
    to improper permissions. This may allow a local attacker 
    to disclose sensitive information. No further details 
    have been provided by the vendor. (CVE-2017-5809)");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbgn03732en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bc6963f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Data Protector 8.17 / 9.09 or later per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5807");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl", "hp_data_protector_installed.nasl", "hp_data_protector_installed_local.nasl");
  script_require_keys("Services/data_protector/version");
  script_require_ports("Services/hp_openview_dataprotector", 5555);

  exit(0);
}

include("hp_data_protector_version.inc");

port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);

# patterns matching affected platforms
hpux_pat = "^11\.(11|23|31)$";
windows_pat = "^(5\.2|6\.\d+)$";
linux_pat = "(el[4-7]|Server release [4-7]|SLES(9|10|11|12))(\.|$|[^0-9])";

# patterns for matching against affected versions
ver_800_pat = "^A\.08\.0[0-9]$|^A\.08\.1[0-6]$";
ver_900_pat = "^A\.09\.0[0-8]$";

## 8.1x

hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_800_pat,
                        fixed_internal_build: 214,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_800_pat,
                        fixed_internal_build: 214,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_800_pat,
                        fixed_internal_build: 214,
                        severity: SECURITY_HOLE,
                        port:port);

## 9.0x

hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_900_pat,
                        fixed_internal_build: 114,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_900_pat,
                        fixed_internal_build: 114,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_900_pat,
                        fixed_internal_build: 114,
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check_exit(port:port);
