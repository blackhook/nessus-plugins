#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83030);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-2116");
  script_bugtraq_id(74249);
  script_xref(name:"HP", value:"emr_na-c04636829");
  script_xref(name:"HP", value:"HPSBMU03321");
  script_xref(name:"HP", value:"SSRT101677");

  script_name(english:"HP Data Protector Multiple Vulnerabilities (HPSBMU03321 SSRT101677)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The HP Data Protector running on the remote host is affected by
multiple unspecified vulnerabilities that can allow a remote attacker
to gain elevated privileges, trigger a denial of service, or execute
arbitrary code with System privileges.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-c04636829
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aac99258");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2116");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl", "hp_data_protector_installed.nasl", "hp_data_protector_installed_local.nasl");
  script_require_keys("Services/data_protector/version");
  script_require_ports("Services/hp_openview_dataprotector", 5555);

  exit(0);
}

include("hp_data_protector_version.inc");

port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);

# patterns matching affected platforms
hpux_pat = "^11\.(11|23|31)$";
windows_pat = "^(5\.2|6\.[012])$";
linux_pat = "(el[4-6]|Server release [4-6]|SLES(9|10|11))(\.|$|[^0-9])";

# patterns for matching against affected versions
ver_700_pat = "^A\.07\.0[01]$";

# 7.00
fixed_build = 107;

hp_data_protector_check(os:"hpux",
                        os_version_pat: hpux_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: fixed_build,
                        patch_prefix: "DPUX",
                        comp_patches: make_array("core", 84, "cell_server", 85,
                                                 "disk_agent", 86, "media_agent", 87,
                                                 "cell_console", 88),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"linux",
                        os_version_pat: linux_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: fixed_build,
                        comp_patches: make_array("core", 372, "cell_server", 373,
                                                 "disk_agent", 374, "media_agent", 375,
                                                 "cell_console", 376),
                        severity: SECURITY_HOLE,
                        port:port);

hp_data_protector_check(os:"windows",
                        os_version_pat: windows_pat,
                        version_pat: ver_700_pat,
                        fixed_internal_build: fixed_build,
                        comp_patches: make_array("core", 790, "cell_server", 791,
                                                 "disk_agent", 792, "media_agent", 793,
                                                 "cell_console", 794),
                        severity: SECURITY_HOLE,
                        port:port);

# Not vuln if we've reached this point.  Exit with correct audit.
hp_data_protector_check_exit(port:port);

