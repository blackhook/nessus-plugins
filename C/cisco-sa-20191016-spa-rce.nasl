#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129982);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2019-12702",
    "CVE-2019-12703",
    "CVE-2019-12704",
    "CVE-2019-15240",
    "CVE-2019-15241",
    "CVE-2019-15242",
    "CVE-2019-15243",
    "CVE-2019-15244",
    "CVE-2019-15245",
    "CVE-2019-15246",
    "CVE-2019-15247",
    "CVE-2019-15248",
    "CVE-2019-15249",
    "CVE-2019-15250",
    "CVE-2019-15251",
    "CVE-2019-15252",
    "CVE-2019-15257",
    "CVE-2019-15258"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq50494");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq50529");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq50503");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq50523");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq50512");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq50520");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-spa-rce");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-spa-webui-dos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-spa-ui-disclosure");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-spa-running-config");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-spa-reflected-xss");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-spa-credentials");

  script_name(english:"Cisco SPA100 Series Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco SPA100 Series device is affected by multiple vulnerabilities:

  - Multiple remote code execution vulnerabilities. An authenticated attacker can cause a stack overflow leading to
    control flow change in the Cisco SPA 112/122 device. (CVE-2019-15240, CVE-2019-15241, CVE-2019-15242,
    CVE-2019-15243, CVE-2019-15244, CVE-2019-15245, CVE-2019-15246, CVE-2019-15247, CVE-2019-15248, CVE-2019-15249,
    CVE-2019-15250, CVE-2019-15251, CVE-2019-15252)

  - Multiple cross-site scripting vulnerabilities. An authenticated attacker can inject javascript on the Cisco SPA
    112/122 device. (CVE-2019-12702, CVE-2019-12703)

  - An arbitrary file disclosure vulnerability. An unauthenticated attacker can read any file on the device and
    elevate local privilege. (CVE-2019-12704)

  - Multiple privilege escalation vulnerabilites. An authenticated attacker can leak the administrator password
    hash to escalate local privilege. (CVE-2019-12708, CVE-2019-15257)

  - A denial of service vulnerability. An authenticated attacker can crash the web service with a malformed
    request. (CVE-2019-12258)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2019-44");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-spa-rce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36518fa8");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-spa-webui-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88204172");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-spa-ui-disclosure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f480f5");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-spa-running-config
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c85940fa");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-spa-reflected-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6a2b0c7");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-spa-credentials
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7615d430");
  script_set_attribute(attribute:"solution", value:
"Upgrade Cisco SPA100 Series to firmware version 1.4.1 SR5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:spa");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:spa");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_spa_web_detection.nbin", "cisco_spa_sip_detection.nbin");
  script_require_keys("installed_sw/Cisco SPA ATA");

  exit(0);
}

include('audit.inc');
include('vcf.inc');
include('http.inc');

app = 'Cisco SPA ATA';

# get all sip ports (tcp or udp)
i = 0;
ports = make_list();
foreach proto (make_list("tcp", "udp"))
{
  if (proto == "tcp")
    list = get_kb_list("Services/sip");
  else
    list = get_kb_list("Services/" + proto + "/sip");

  if (empty_or_null(list))
    continue;

  list = make_list(list);
  foreach port (list)
    ports[i++] = make_list(proto, port);
}

if (i != 0)
{
  # branch on sip, taking one protocol:port pair each
  pair = branch(ports);
  proto = pair[0];
  port = pair[1];
  webapp = FALSE;
}
else
{
  # no sip, fall back to branching on http
  port = get_http_port(default:80);
  proto = "tcp";
  webapp = TRUE;
}

vuln = FALSE;

app_info = vcf::get_app_info(app:app, port:port, proto:proto, webapp:webapp);

# patch is 1.4.1 SR5
if (app_info.main_version == "1.4.1")
{
  if (ver_compare(ver:app_info.sr_version, fix:"5") < 0)
    vuln = TRUE;
}
else if (ver_compare(ver:app_info.main_version, fix:"1.4.1") < 0)
  vuln = TRUE;

if (!vuln)
  audit(AUDIT_DEVICE_NOT_VULN, app, app_info.version);

vcf::report_results(app_info:app_info, fix:"1.4.1 (SR5)", severity:SECURITY_WARNING, flags:{xss:TRUE});

