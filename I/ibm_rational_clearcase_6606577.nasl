#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172123);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/05");

  script_cve_id(
    "CVE-2022-27774",
    "CVE-2022-27778",
    "CVE-2022-27779",
    "CVE-2022-27780",
    "CVE-2022-27782",
    "CVE-2022-30115"
  );
  script_xref(name:"IAVB", value:"2022-B-0023");

  script_name(english:"IBM Rational ClearCase 8.0 < 9.0.1.14 / 9.0.2 < 9.0.2.6 / 9.1 < 9.1.0.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The IBM Rational ClearCase installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Rational ClearCase installed on the remote host is affected by multiple vulnerabilities, including
the following:

  - A use of incorrectly resolved name vulnerability fixed in 7.83.1 might remove the wrong file when
    '--no-clobber' is used together with '--remove-on-error'. (CVE-2022-27778)

  - The curl URL parser wrongly accepts percent-encoded URL separators like '/' when decoding the host name
    part of a URL, making it a *different* URL using the wrong host name when it is later retrieved. For
    example, a URL like 'http://example.com%2F127.0.0.1/', would be allowed bythe parser and get transposed
    into 'http://example.com/127.0.0.1/'. This flaw can be used to circumvent filters, checks and more.
    (CVE-2022-27780)

  - libcurl would reuse a previously created connection even when a TLS or SSH related option had been changed
    that should have prohibited reuse. libcurl keeps previously used connections in a connection pool for
    subsequent transfers to reuse if one of them matches the setup. However, several TLS and SSH settings were
    left out from the configuration match checks, making them match too easily. (CVE-2022-27782)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6606577");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Rational ClearCase Fix Pack 14 (9.0.1.14) for 9.0, Fix Pack 6 (9.0.2.6) for 9.0.2, Fix Pack 3
(9.1.0.3) for 9.1, or later. See vendor advisory for 8.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27778");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearcase");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_rational_clearcase_win_installed.nbin");
  script_require_keys("installed_sw/IBM Rational ClearCase");

  exit(0);
}
include('vcf.inc');

var app = 'IBM Rational ClearCase';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '8.0',   'fixed_version' : '8.9.9.9', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '9.0',   'fixed_version' : '9.0.1.14'},
  { 'min_version' : '9.0.2', 'fixed_version' : '9.0.2.6' },
  { 'min_version' : '9.1',   'fixed_version' : '9.1.0.3' }
];
  
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
