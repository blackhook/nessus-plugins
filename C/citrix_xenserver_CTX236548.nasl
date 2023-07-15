#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111789);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-3620", "CVE-2018-3646", "CVE-2018-14007");
  script_bugtraq_id(105080, 105110);

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (Foreshadow) (CTX236548)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by multiple vulnerabilities
including L1 Terminal Fault (L1TF) and a local code execution vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX236548");
  script_set_attribute(attribute:"see_also", value:"https://foreshadowattack.eu/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14007");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::xenserver::get_app_info();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { "equal" : "7.0",    "patches" : [     # XenServer 7.0
                          "XS70E060",     # CTX237090
                          "XS70E061" ]    # CTX237092
  },
  { "min_version" : "7.1", "max_version" : "7.1.1",
                        "patches" : [     # XenServer 7.1 LTSR CU1
                          "XS71ECU1024",  # CTX236908
                          "XS71ECU1026",  # CTX237088
                          "XS71ECU1027" ] # CTX237089
  },
  { "equal" : "7.4",    "patches" : [     # XenServer 7.4
                          "XS74E005",     # CTX236909
                          "XS74E006",     # CTX237086
                          "XS74E007" ]    # CTX237087
  },
  { "equal" : "7.5",      "patches" : [   # XenServer 7.5
                          "XS75E003",     # CTX236910
                          "XS75E004",     # CTX237085
                          "XS75E005" ]    # CTX237080
  }
];

vcf::xenserver::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
