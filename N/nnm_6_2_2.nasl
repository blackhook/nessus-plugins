#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177842);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2010-4008",
    "CVE-2010-4494",
    "CVE-2011-1202",
    "CVE-2011-1944",
    "CVE-2011-3970",
    "CVE-2012-0841",
    "CVE-2012-2870",
    "CVE-2012-2871",
    "CVE-2012-5134",
    "CVE-2012-6139",
    "CVE-2013-0338",
    "CVE-2013-0339",
    "CVE-2013-1969",
    "CVE-2013-2877",
    "CVE-2013-4520",
    "CVE-2014-3660",
    "CVE-2015-5312",
    "CVE-2015-7497",
    "CVE-2015-7498",
    "CVE-2015-7499",
    "CVE-2015-7500",
    "CVE-2015-7941",
    "CVE-2015-7942",
    "CVE-2015-7995",
    "CVE-2015-8035",
    "CVE-2015-8241",
    "CVE-2015-8242",
    "CVE-2015-8317",
    "CVE-2015-8710",
    "CVE-2015-8806",
    "CVE-2015-9019",
    "CVE-2016-1683",
    "CVE-2016-1684",
    "CVE-2016-1762",
    "CVE-2016-1833",
    "CVE-2016-1834",
    "CVE-2016-1836",
    "CVE-2016-1837",
    "CVE-2016-1838",
    "CVE-2016-1839",
    "CVE-2016-1840",
    "CVE-2016-2073",
    "CVE-2016-3189",
    "CVE-2016-3627",
    "CVE-2016-3705",
    "CVE-2016-3709",
    "CVE-2016-4447",
    "CVE-2016-4448",
    "CVE-2016-4449",
    "CVE-2016-4483",
    "CVE-2016-4607",
    "CVE-2016-4609",
    "CVE-2016-4658",
    "CVE-2016-5131",
    "CVE-2016-5180",
    "CVE-2016-9596",
    "CVE-2016-9597",
    "CVE-2016-9598",
    "CVE-2017-5029",
    "CVE-2017-5130",
    "CVE-2017-5969",
    "CVE-2017-7375",
    "CVE-2017-7376",
    "CVE-2017-8872",
    "CVE-2017-9047",
    "CVE-2017-9048",
    "CVE-2017-9049",
    "CVE-2017-9050",
    "CVE-2017-15412",
    "CVE-2017-16931",
    "CVE-2017-16932",
    "CVE-2017-18258",
    "CVE-2017-1000061",
    "CVE-2017-1000381",
    "CVE-2018-9251",
    "CVE-2018-14404",
    "CVE-2018-14567",
    "CVE-2019-5815",
    "CVE-2019-8457",
    "CVE-2019-9936",
    "CVE-2019-9937",
    "CVE-2019-11068",
    "CVE-2019-12900",
    "CVE-2019-13117",
    "CVE-2019-13118",
    "CVE-2019-16168",
    "CVE-2019-19242",
    "CVE-2019-19244",
    "CVE-2019-19317",
    "CVE-2019-19603",
    "CVE-2019-19645",
    "CVE-2019-19646",
    "CVE-2019-19880",
    "CVE-2019-19923",
    "CVE-2019-19924",
    "CVE-2019-19925",
    "CVE-2019-19926",
    "CVE-2019-19956",
    "CVE-2019-19959",
    "CVE-2019-20218",
    "CVE-2019-20388",
    "CVE-2019-20838",
    "CVE-2020-7595",
    "CVE-2020-9327",
    "CVE-2020-11655",
    "CVE-2020-11656",
    "CVE-2020-13434",
    "CVE-2020-13435",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632",
    "CVE-2020-13871",
    "CVE-2020-14155",
    "CVE-2020-15358",
    "CVE-2020-24977",
    "CVE-2020-35525",
    "CVE-2020-35527",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537",
    "CVE-2021-3541",
    "CVE-2021-3672",
    "CVE-2021-20227",
    "CVE-2021-30560",
    "CVE-2021-31239",
    "CVE-2021-36690",
    "CVE-2021-45346",
    "CVE-2022-4904",
    "CVE-2022-22576",
    "CVE-2022-23308",
    "CVE-2022-23395",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-29824",
    "CVE-2022-31160",
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208",
    "CVE-2022-32221",
    "CVE-2022-35252",
    "CVE-2022-35737",
    "CVE-2022-40303",
    "CVE-2022-40304",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2022-43551",
    "CVE-2022-43552",
    "CVE-2022-46908",
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-1255",
    "CVE-2023-2650",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-23916",
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27538",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322",
    "CVE-2023-28484",
    "CVE-2023-29469",
    "CVE-2023-31124",
    "CVE-2023-31130",
    "CVE-2023-31147",
    "CVE-2023-32067"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Nessus Network Monitor < 6.2.2 Multiple Vulnerabilities (TNS-2023-23)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable NNM installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Nessus Network Monitor running on the remote host is prior to 6.2.2. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-23 advisory. Several of the third-party 
components were found to contain vulnerabilities, and updated versions have been made available by the providers. 
Out of caution and in line with best practice, Tenable has opted to upgrade these components to address the potential 
impact of the issues. Nessus Network Monitor 6.2.2 updates the following components:

  - c-ares from version 1.10.0 to version 1.19.1.
  - curl from version 7.79.1 to version 8.1.2.
  - libbzip2 from version 1.0.6 to version 1.0.8.
  - libpcre from version 8.42 to version 8.44.
  - libxml2 from version 2.7.7 to version 2.11.1.
  - libxslt from version 1.1.26 to version 1.1.37.
  - libxmlsec from version 1.2.18 to version 1.2.37.
  - sqlite from version 3.27.2 to version 3.40.1.
  - jQuery Cookie from version 1.3.1 to version 1.4.1.
  - jQuery UI from version 1.13.0 to version 1.13.2.
  - OpenSSL from version 3.0.8 to version 3.0.9.");
  script_set_attribute(attribute:"see_also", value:"https://docs.tenable.com/releasenotes/Content/nnm/2023nnm.htm");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-23");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor 6.2.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7376");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable NNM';

var app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '6.2.1', 'fixed_version' : '6.2.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
