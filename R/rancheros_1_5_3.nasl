#
# (C) Tenable Network Security, Inc.
#

# @NOAGENT@

include('compat.inc');

if (description)
{
  script_id(132257);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479");
  script_bugtraq_id(108798, 108801, 108818);
  script_xref(name:"CEA-ID", value:"CEA-2019-0456");

  script_name(english:"RancherOS < 1.5.3 Multiple Vulnerabilities (SACK Panic)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of RancherOS prior to v1.5.3, hence
is exposed to multiple vulnerabilities:


  - Linux Kernel is prone to a remote integer-overflow vulnerability.
    An attacker can exploit this issue to cause denial-of-service
    conditions. (CVE-2019-11477)

  - RancherOS is vulnerable to a denial of service; by crafting a
    sequence of SACKs, an attacker can cause fragmentation of the
    TCP transmission queue, leading to higher resource use. 
    (CVE-2019-11478)

  - Linux kernel default MSS is hard-coded to 48 bytes. This allows
    a remote peer to fragment TCP resend queues significantly more
    than if a larger MSS were enforced. A remote attacker could use
    this to cause a denial of service. (CVE-2019-11479)");
  script_set_attribute(attribute:"see_also", value:"https://rancher.com/docs/os/v1.x/en/about/security/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rancher/os/releases/tag/v1.5.3");
  script_set_attribute(attribute:"see_also", value:"https://lwn.net/Articles/791409/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RancherOS v1.5.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11477");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rancher:rancheros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint_linux_distro.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RancherOS/version", "Host/RancherOS");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Fix version is v1.5.3
fix_version = '1.5.3';
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
      severity:SECURITY_HOLE,
      extra:
        '\n  Installed version : ' + os_ver +
        '\n  Fixed version     : v' + fix_version +
        '\n'
    );
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'RancherOS', os_ver);