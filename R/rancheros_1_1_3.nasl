#
# (C) Tenable Network Security, Inc.
#
# @NOAGENT@

include('compat.inc');

if (description)
{
  script_id(132250);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/19");

  script_cve_id("CVE-2017-5754");
  script_bugtraq_id(102378);

  script_name(english:"RancherOS < 1.1.3 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of RancherOS that is prior to
v1.1.3, hence is vulnerable to local privilege-escalation vulnerability. 
An attacker can exploit this issue to cause a denial-of-service condition.

Systems with microprocessors utilizing speculative execution and
indirect branch prediction may allow unauthorized disclosure of
information to an attacker with local user access via a side-channel
analysis of the data cache.");
  script_set_attribute(attribute:"see_also", value:"https://rancher.com/docs/os/v1.x/en/about/security/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rancher/os/releases/tag/v1.1.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RancherOS v1.1.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5754");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rancher:rancheros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint_linux_distro.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RancherOS/version", "Host/RancherOS");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Fix version is v1.1.3
fix_version = '1.1.3';
os = get_kb_item('Host/RancherOS');

if (!os) audit(AUDIT_OS_NOT, 'RancherOS');

os_ver = get_kb_item('Host/RancherOS/version');
if (!os_ver)
{
  exit(1, 'Could not determine the RancherOS version');
}

match = pregmatch(pattern:"v([0-9\.]+)", string:os_ver);

if (!isnull(match))
{ 
  version = match[1]; 
  if (ver_compare(ver:version, fix:fix_version, strict:TRUE) == -1)
  {
    security_report_v4(
      port:0,
      severity:SECURITY_WARNING,
      extra:
        '\n  Installed version : ' + os_ver +
        '\n  Fixed version     : v' + fix_version +
        '\n'
    );
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'RancherOS', os_ver);