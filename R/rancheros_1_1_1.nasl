#
# (C) Tenable Network Security, Inc.
#

# @NOAGENT@

include('compat.inc');

if (description)
{
  script_id(132249);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2017-6074");
  script_bugtraq_id(102032);

  script_name(english:"RancherOS < 1.1.1 Privilege Escalation (Dirty COW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of RancherOS that is prior to v.1.1.1, hence is vulnerable to a privilege
escalation vulnerability.

The Linux Kernel versions 2.6.38 through 4.14 have a problematic use of pmd_mkdirty() in the touch_pmd() function
inside the THP implementation. touch_pmd() can be reached by get_user_pages(). In such case, the pmd will become
dirty. This scenario breaks the new can_follow_write_pmd()'s logic - pmd can become dirty without going through a
COW cycle. This bug is not as severe as the original Dirty cow because an ext4 file (or any other regular file)
cannot be mapped using THP. Nevertheless, it does allow us to overwrite read-only huge pages. For example, the zero
huge page and sealed shmem files can be overwritten (since their mapping can be populated using THP). Note that after
the first write page-fault to the zero page, it will be replaced with a new fresh (and zeroed) thp.");
  script_set_attribute(attribute:"see_also", value:"https://rancher.com/docs/os/v1.x/en/about/security/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rancher/os/releases/tag/v1.1.1");
  script_set_attribute(attribute:"solution", value:
"Update to RancherOS v1.1.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6074");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rancher:rancheros");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint_linux_distro.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RancherOS/version", "Host/RancherOS");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Fix version is v1.1.1
fix_version = '1.1.1';
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
