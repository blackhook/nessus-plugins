#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130589);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2015-9251",
    "CVE-2016-7103",
    "CVE-2019-1559",
    "CVE-2019-2897",
    "CVE-2019-2898",
    "CVE-2019-2900",
    "CVE-2019-2905",
    "CVE-2019-2906",
    "CVE-2019-3012"
  );
  script_bugtraq_id(104823, 105658, 107174);
  script_xref(name:"IAVA", value:"2019-A-0382");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Business Intelligence Publisher Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Publisher running on the
remote host is 11.1.1.9.x prior to 11.1.1.9.191015 or 12.2.1.3.x 
prior to 12.2.1.3.191015 or 12.2.1.4.x prior to 12.2.1.4.191015. 
It is, therefore, affected by  multiple vulnerabilities as noted in
the October 2019 Critical Patch Update advisory:

  - An unspecified vulnerability in the Installation
    component of Oracle BI Publisher that allows
    unauthenticated attacker with network access via HTTP
    to compromise Oracle BI Publisher. While the
    vulnerability is in Oracle BI Publisher, attacks
    may significantly impact additional products.
    Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access
    to all Oracle BI Publisher accessible data.
    (CVE-2019-2905)

  - An unspecified vulnerability in the MobileService
    component of Oracle BI Publisher could allow an
    unauthenticated attacker with network access via HTTP
    to compromise BI Publisher. A successful attack requires
    human interaction from a person other than the attacker
    and while the vulnerability is in BI Publisher, attacks
    may significantly impact additional products.
    (CVE-2019-2906)

  - An unspecified vulnerability in the BI PublisherSecurity
    component of Oracle BI Publisher could allow a low
    privileged attacker with networkaccess via HTTP to
    compromise Oracle BI Publisher. A successful attack of
    this vulnerability canresult in unauthorized read access
    to a subset of BIPublisher accessible data
    (CVE-2019-2898)

  - An unspecified vulnerability in the Analytics Actions
  component of Oracle BI Publisher could allow a low
  privileged attacker with network access via HTTP to
  compromise Oracle BI Publisher. While the vulnerability
  is in Oracle BI Publisher, attacks may significantly
  impact additional products. Successful attacks of this
  vulnerability can result in unauthorized update, insert
  or delete access to some of Oracle BI Publisher
  accessible data as well as unauthorized read access to
  a subset of Oracle BI Publisher accessible data.
  (CVE-2019-2897)

  - An unspecified vulnerability in the Secure Store
    (OpenSSL) component of Oracle BI Publisher could allow
    an unauthenticated attacker with network access via
    HTTPS to compromise Oracle BI Publisher. Successful
    attacks of this vulnerability can result in
    unauthorized access to critical data or complete
    access to all Oracle BI Publisher data.
    (CVE-2019-1559)
  
  - An unspecified vulnerability in the BI Platform
    Security (JQuery) component of Oracle BI Publisher
    could allow an unauthenticated attacker with network
    access via HTTP to compromise Oracle BI Publisher.
    Successful attacks require human interaction from a
    person other than the attacker and while the
    vulnerability is in Oracle BI Publisher, attacks may
    significantly impact additional products.
    (CVE-2016-7103)

  - An unspecified vulnerability in the Analytics Actions
    component of Oracle BI Publisher could allow an
    unauthenticated attacker with network access via HTTP to
    compromise Oracle BI Publisher. Successful attacks of
    this vulnerability can result in unauthorized access to
    critical data or complete access to all Oracle BI
    Publisher accessible data. (CVE-2019-2900)

  - An unspecified vulnerability in the BI Platform
    Security component of Oracle BI Publisher could allow
    an unauthenticated attacker with network access via
    HTTP to compromise Oracle BI Publisher. Successful
    attacks of this vulnerability can result in
    unauthorized read access to a subset of Oracle BI
    Publisher accessible data. (CVE-2019-3012)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/security-alerts/cpuoct2019.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c94f8e4");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2019 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2906");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2905");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence_publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bi_publisher_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Publisher");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');
appname = 'Oracle Business Intelligence Publisher';
app_info = vcf::get_app_info(app:appname);

# 11.1.1.9.x - Bundle: 30386665 | Patch: 30406851
# 12.2.1.3.x - Bundle: 30349417 | Patch: 30349417
# 12.2.1.4.x - Bundle: 30344570 | Patch: 30344570
constraints = [
  {'min_version': '11.1.1.9', 'fixed_version': '11.1.1.9.191015', 'patch': '30406851', 'bundle': '30386665'},
  {'min_version': '12.2.1.3', 'fixed_version': '12.2.1.3.191015', 'patch': '30349417', 'bundle': '30349417'},
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.191015', 'patch': '30344570', 'bundle': '30344570'}
];

vcf::oracle_bi_publisher::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);
