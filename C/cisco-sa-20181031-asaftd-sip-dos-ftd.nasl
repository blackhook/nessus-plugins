#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118822);
  script_version("1.6");
  script_cvs_date("Date: 2020/01/09");

  script_cve_id("CVE-2018-15454");
  script_bugtraq_id(105768);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm43975");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181031-asaftd-sip-dos");

  script_name(english:"Cisco Firepower Threat Defense (FTD) Adaptive Security Appliance Denial of Service Vulnerability (cisco-sa-20181031-asaftd-sip-dos)");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense.");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Cisco Firepower Threat Defense (FTD)
software installed on the remote host is affected by a denial of
service vulnerability which could allow an unauthenticated, remote
attacker to cause a reload of the affected system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181031-asaftd-sip-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80f71c25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a fixed version referenced in the Cisco advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('misc_func.inc');
include('global_settings.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Cisco Firepower Threat Defense";

# Based on the advisory, it seems we're looking only for FTD and not FXOS
app_info = vcf::get_app_info(app:app);

ver = app_info['version'];

if (isnull(ver)) audit(AUDIT_HOST_NOT, app);

if (ver =~ "^6\.0\.[01]($|\.)")
  fix = "6.1.0.7";
else if (ver =~ "^6\.1\.0($|\.)")
  fix = "6.1.0.7";
else if (ver =~ "^6\.2\.0($|\.)")
  fix = "6.2.0.6";
else if (ver =~ "^6\.2\.[12]($|\.)")
  fix = "6.2.2.4";
else if (ver =~ "^6\.2\.3($|\.)")
  fix = "6.2.3.7";
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Cisco bug ID      : CSCvm43975' +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
} else audit(AUDIT_INST_VER_NOT_VULN, app, ver);
