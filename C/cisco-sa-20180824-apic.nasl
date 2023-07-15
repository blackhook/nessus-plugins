#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123415);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2018-5391");
  script_bugtraq_id(105108);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180824-linux-ip-fragment");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm15454");

  script_name(english:"Cisco Application Policy Infrastructure Controller Linux Kernel IP Fragment Reassembly DoS");
  script_summary(english:"Checks the Cisco Application Policy Infrastructure Controller (APIC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a Linux Kernel DoS.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Application
Policy Infrastructure Controller (APIC) is affected by a
vulnerability in the IP stack that is used by the Linux Kernel
publicly known as FragmentSmack.

The vulnerability could allow an unauthenticated, remote attacker
to cause a denial of service (DoS) condition on an affected device.
An attack could be executed by an attacker who can submit a stream
of fragmented IPv4 or IPv6 packets that are designed to trigger the
issue on an affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180824-linux-ip-fragment
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d625ffb");
  # https://tools.cisco.com/bugsearch/bug/CSCvm15454
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15f05a53");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Application Policy Infrastructure Controller to 3.2.4 / 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5391");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:application_policy_infrastructure_controller_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");


  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");
   script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("http.inc");
include("install_func.inc");

app = "Cisco APIC Software";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
dir = install['path'];
install_url = build_url(port:port, qs:dir);

if (cisco_gen_ver_compare(a:version, b:'3.2(3.6a)') < 0)
{
  report = '\n  URL               : ' + install_url +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : 3.2.4 / 4.0 or later' +
           '\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);

