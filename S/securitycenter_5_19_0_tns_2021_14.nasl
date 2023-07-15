#%NASL_MIN_LEVEL 70300
##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/09/03. Deprecated by securitycenter_5_19_0_tns_2021_08_XSS.nasl
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151985);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id(
    "CVE-2016-10735",
    "CVE-2017-5661",
    "CVE-2018-14040",
    "CVE-2018-14042",
    "CVE-2018-20676",
    "CVE-2018-20677",
    "CVE-2019-8331",
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-11043",
    "CVE-2019-11044",
    "CVE-2019-11045",
    "CVE-2019-11046",
    "CVE-2019-11047",
    "CVE-2019-11048",
    "CVE-2019-11049",
    "CVE-2019-11050",
    "CVE-2019-16168",
    "CVE-2019-19645",
    "CVE-2019-19646",
    "CVE-2019-19919",
    "CVE-2020-7059",
    "CVE-2020-7060",
    "CVE-2020-7061",
    "CVE-2020-7062",
    "CVE-2020-7063",
    "CVE-2020-7064",
    "CVE-2020-7065",
    "CVE-2020-7066",
    "CVE-2020-7067",
    "CVE-2020-7068",
    "CVE-2020-7069",
    "CVE-2020-7070",
    "CVE-2020-7071",
    "CVE-2020-11022",
    "CVE-2020-11655",
    "CVE-2020-11656",
    "CVE-2020-13434",
    "CVE-2020-13435",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632",
    "CVE-2020-15358",
    "CVE-2021-21702",
    "CVE-2021-21704",
    "CVE-2021-21705",
    "CVE-2021-23358"
  );

  script_name(english:"Tenable.sc < 5.19.0 Multiple Vulnerabilities (TNS-2021-14) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated by plugin 152985 and 152986.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-14");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5661");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter", "installed_sw/Tenable SecurityCenter");

  exit(0);
}

exit(0, 'This plugin has been deprecated. Use plugins 152985 and 152986 instead.');
