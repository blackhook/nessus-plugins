#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(122129);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id(
    "CVE-2018-3147",
    "CVE-2018-3217",
    "CVE-2018-3218",
    "CVE-2018-3219",
    "CVE-2018-3220",
    "CVE-2018-3221",
    "CVE-2018-3222",
    "CVE-2018-3223",
    "CVE-2018-3224",
    "CVE-2018-3225",
    "CVE-2018-3226",
    "CVE-2018-3227",
    "CVE-2018-3228",
    "CVE-2018-3229",
    "CVE-2018-3230",
    "CVE-2018-3231",
    "CVE-2018-3232",
    "CVE-2018-3233",
    "CVE-2018-3234",
    "CVE-2018-3302",
    "CVE-2018-18223",
    "CVE-2018-18224",
    "CVE-2019-0686",
    "CVE-2019-0724"
  );
  script_xref(name:"MSKB", value:"4345836");
  script_xref(name:"MSKB", value:"4471391");
  script_xref(name:"MSKB", value:"4471392");
  script_xref(name:"MSKB", value:"4487052");
  script_xref(name:"MSFT", value:"MS19-4345836");
  script_xref(name:"MSFT", value:"MS19-4471391");
  script_xref(name:"MSFT", value:"MS19-4471392");
  script_xref(name:"MSFT", value:"MS19-4487052");

  script_name(english:"Security Updates for Exchange (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing
security updates. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple Vulnerabilites with the included libraries from
    Oracle Outside. (CVE-2018-18223, CVE-2018-18224,
    CVE-2018-3147, CVE-2018-3217, CVE-2018-3218, CVE-2018-3219,
    CVE-2018-3220, CVE-2018-3221, CVE-2018-3222, CVE-2018-3223,
    CVE-2018-3224, CVE-2018-3225, CVE-2018-3226, CVE-2018-3227,
    CVE-2018-3228, CVE-2018-3229, CVE-2018-3230, CVE-2018-3231,
    CVE-2018-3232, CVE-2018-3233, CVE-2018-3234, CVE-2018-3302)

  - An elevation of privilege vulnerability exists in
    Exchange Web Services and Push Notifications. An
    unauthenticated, remote attacker can exploit, via a
    man-in-the-middle attack forwarding an authentication
    request to the Domain Controller, to gain any users
    privileges. (CVE-2019-0686)

  - An elevation of privilege vulnerability exists in
    Exchange Web Services and Push Notifications. An
    unauthenticated, remote attacker can exploit, via a
    man-in-the-middle attack forwarding an authentication
    request to the Domain Controller, to gain Domain
    Administrator privileges. (CVE-2019-0724)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4345836");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4471391");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4471392");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4487052");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4345836
  -KB4471391
  -KB4471392
  -KB4487052");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0724");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::exchange::get_app_info();

var constraints =
[
  {
    'product' : '2010',
    'min_version': '14.3.0.0',
    'fixed_version': '14.03.442.0',
    'kb': '4487052'
  },
   {
    'product' : '2013',
    'min_version': '15.00.1473.0',
    'fixed_version': '15.00.1473.3',
    'kb': '4345836'
  },
  {
    'product' : '2016',
    'min_version': '15.01.1713.0',
    'fixed_version': '15.01.1713.5',
    'kb': '4471392'
  },
  {
    'product' : '2019',
    'min_version': '15.02.330.0',
    'fixed_version': '15.02.330.5',
    'kb': '4471391'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS19-02',
  constraints:constraints,
  severity:SECURITY_WARNING
);