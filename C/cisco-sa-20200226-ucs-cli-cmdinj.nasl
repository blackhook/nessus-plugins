#TRUSTED 8721b4eeec02029b81bd976d09e65fe04ca86ba9a40228fbf59b67fd19b9ef1120d9c467560bac0b9f649129a771f154483513a19b0060821513cd6c1857f06d9061ab8e9a456f89f69006cce02b4bbfa25c5f9ea8574d53470b932183984341cb0fbd8e5105f75f7514e149b4be1356c90561d2fda438dc5f8722eecde49fd7a89848dbb55a69060db0756f6b706aa1b16057674e152d074326d4c75c0934700304df9c008fc7d6c37d5826c0939e943480c1919df2c7cd34677a0a47f370a4c3252e1e4e21c9a9e9cf31006da2c98a844e1a2dd207626017bd85aa7a0ef2e6a2420d6dcaef3e01ebff894846ec1d30e80aafe98f548739c37d647237847d961aa423373fad4a100f37280003946e013f8c71fbfc4b650d9e741703aa4a2bac392d9aa33257d023adce3ffb6debfcde7d7d9fb43906f222b8af9342f77abadd644ccecfc7f75c0d032f931512506d4b82e4e4df0713bde5ba7bbde82cbf0f1479a40c268bfee9d53ffd09448924ae92170433ed994e8abeabfef2905629cff1312053bd37ff17dd54caa554def32cefc7a6ff0a4932c7f57062483ba1b7759e765479e8c99e1df7707033a4e7675cd51c5be1251d7971225288d767b93faa9f4a569fd2113b7fee947987c0b1bc470f241102f1d68e6adefda1bd7c05122226b831d40d3e0c2f1e18e4402387a5f7567888b3b2ce99bc7a1df6f9040bca4d3c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140203);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2020-3173");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq57926");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-ucs-cli-cmdinj");

  script_name(english:"Cisco UCS Manager Software Local Management CLI Command Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unified Computing System (Managed) is affected by a vulnerability. Please
see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-ucs-cli-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eea03d8c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73749");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq57926");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq57926");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:unified_computing_system_(managed)");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('audit.inc');
include('http.inc');
include('install_func.inc');
include('cisco_func.inc');
include('audit.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'cisco_ucs_manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
version = tolower(install['version']);

if (
    ( cisco_gen_ver_compare(a:version, b:'0.0') >= 0 &&
      cisco_gen_ver_compare(a:version, b:'3.2(3n)') < 0
    ) ||
    ( cisco_gen_ver_compare(a:version, b:'4.0') >= 0 &&
      cisco_gen_ver_compare(a:version, b:'4.0(4c)') < 0
    )
)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : See vendor.' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);

