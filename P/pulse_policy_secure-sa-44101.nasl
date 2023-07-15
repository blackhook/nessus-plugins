#
# (c) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124767);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-11509",
    "CVE-2019-11539",
    "CVE-2019-11540",
    "CVE-2019-11542",
    "CVE-2019-11543"
  );
  script_bugtraq_id(108073);
  script_xref(name:"IAVA", value:"2019-A-0309-S");
  script_xref(name:"IAVA", value:"0001-A-0001-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0122");
  script_xref(name:"CEA-ID", value:"CEA-2019-0656");

  script_name(english:"Pulse Policy Secure Multiple Vulnerabilities (SA44101)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Policy
Secure running on the remote host is affected by multiple
vulnerabilities.

   - A session hijacking vulnerability exists in PPS. An
     unauthenticated, remote attacker can exploit this, to perform
     actions in the user or administrator interface with the
     privileges of another user. (CVE-2019-11540)

   - Multiple vulnerabilities found in the admin web interface of PPS
     (CVE-2019-11543, CVE-2019-11542, CVE-2019-11539, CVE-2019-11509)

   - Multiple vulnerabilities found in Network File Share (NFS) of PPS
     , allows the attacker to read/write arbitrary files on the
     affected device. (CVE-2019-11538, CVE-2019-11508)

Refer to the vendor advisory for additional information.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d23f9165");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate version referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11540");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pulse Secure VPN Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_policy_secure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_policy_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Policy Secure");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:'Pulse Policy Secure', port:443);

constraints = [
  {'min_version' : '5.1R1' , 'fixed_version' : '5.1R15.1'},
  {'min_version' : '5.2R1' , 'fixed_version' : '5.2R12.1'},
  {'min_version' : '5.3R1' , 'fixed_version' : '5.3R12.1'},
  {'min_version' : '5.4R1' , 'fixed_version' : '5.4R7.1.'},
  {'min_version' : '9.0R1' , 'fixed_version' : '9.0R3.2', 'display_version' : '9.0R3.2 / 9.0R4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
