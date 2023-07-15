#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133401);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2020-3139");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs10135");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iptable-bypass-GxW88XjL");
  script_xref(name:"IAVA", value:"2020-A-0043-S");

  script_name(english:"Cisco Application Policy Infrastructure Controller Out Of Band Management IP Tables Bypass (cisco-sa-iptable-bypass-GxW88XjL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller (APIC) is affected by a
vulnerability in the out of band (OOB) management interface IP table rule programming. This is due to the configuration
of specific IP table entries for which there is a programming logic error that results in the IP port being permitted.
An unauthenticated, remote attacker can exploit this, by sending traffic to the OOB management interface, in order to
bypass configured IP table rules to drop specific IP port traffic or bypass configured deny entries for specific IP
ports. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iptable-bypass-GxW88XjL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c63345bb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs10135");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs10135");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3139");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:application_policy_infrastructure_controller_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include('audit.inc');
include('cisco_func.inc');
include('http.inc');
include('install_func.inc');

app = 'Cisco APIC Software';
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
dir = install['path'];
install_url = build_url(port:port, qs:dir);

if (cisco_gen_ver_compare(a:version, b:'4.2(3j)') < 0)
{
  report = '\n  URL               : ' + install_url +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : 4.2(3j) or later' +
           '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
