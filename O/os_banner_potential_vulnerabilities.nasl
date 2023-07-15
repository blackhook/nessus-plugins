#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108591);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/22");

  script_name(english:"OS vulnerabilities detected in banner reporting (PCI-DSS check)");
  script_summary(english:"Checks banners for vulnerable OS levels");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The OS version reported in banners possesses one or more
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A service banner response from the remote host indicates an OS 
install at a level that may be vulnerable to one or more
vulnerabilities.

This plugin only runs when 'Check for PCI-DSS compliance' is enabled
in the scan policy. It does not run if local security checks are
enabled. It runs off of self-reported OS versions in banners and
fingerprinting."
  );

  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/");
  script_set_attribute(attribute:"see_also", value:"https://lists.centos.org/pipermail/centos-announce/");
  script_set_attribute(attribute:"see_also", value:"https://lists.vmware.com/pipermail/security-announce/");
  script_set_attribute(attribute:"see_also", value:"https://usn.ubuntu.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.vuxml.org/freebsd/");

  script_set_attribute(
    attribute:"solution",
    value:
"Update the version of the OS running on the system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl", "os_fingerprint.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("os_cves.inc");
include("lists.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);
if (get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are enabled.");

# Check all relevant banner KBs
banners = get_kb_list("*/banner/*");
host_os = get_kb_item("Host/OS");
if (isnull(banners) && isnull(host_os)) exit(0, "Relevant banners and Host/OS keys not present for this scan.");

# Determine if a supported OS version is present in the banners and extract it
port = 0;
version = NULL;
os = NULL;
regex_list = [
  "(CentOS) release (\d+(?:\.\d+)*)",
  "(FreeBSD)(?:\s*|\/)(\d+\.\d+)-RELEASE",
  "(VMware) ESX Server (\di?) (\d.\d(?:\.\d)?)",
  "(Ubuntu) (\d+\.\d+) \(\w+\)",
  "(Fedora) release (\d+)"
];
foreach banner_kb (sort(keys(banners)))
{
  banner_value = banners[banner_kb];
  foreach regex (regex_list)
  {
    os_version = pregmatch(string:banner_value, pattern:regex, icase:TRUE);
    if(!isnull(os_version))
    {
      os = os_version[1];
      version = os_version[2];
      # Individual fixes for specific OSes
      if (tolower(os) == "vmware")
      {
        version = "ESX";
        if (os_version[2] =~ "i$")
        {
          version += "i";
        }
        version += " " + os_version[3];
      }
      # Try and extract port from banner_kb
      portmatch = pregmatch(pattern:"\/(\d+)(?:\/|$)", string:banner_kb);
      if (portmatch)
      {
        port = portmatch[1];
      }
      break;
    }
  }
}

if (isnull(version))
{
  # Try to get the value from Host/OS
  if (!empty_or_null(host_os))
  {
    foreach regex (regex_list)
    {
      os_version = pregmatch(string:host_os, pattern:regex, icase:TRUE);
      if(!isnull(os_version))
      {
        os = os_version[1];
        version = os_version[2];
        # Individual fixes for specific OSes
        if (tolower(os) == "vmware")
        {
          version = "ESX";
          if (os_version[2] =~ "i$")
          {
            version += "i";
          }
          version += " " + os_version[3];
        }
        break;
      }
    }
  }
}

if (isnull(version) || isnull(os))
{
  exit(0, "Unable to find OS version strings in banner(s) or Host/OS KB entries.");
}

report = 'OS version: ' + os + ' ' + version +
         '\nVulnerabilities potentially exist associated with potentially\n' + 
         'unpatched fixes.\n';
os_vuln_cves = NULL;
os = tolower(os);

advisories_per_line = 4;
if (os == 'centos')
{
  os_vuln_cves = _centos_vuln_cves;
  version_split = split(version, sep:'.', keep:0);
  version = version_split[0];
}
if (os == 'fedora')
{
  os_vuln_cves = _fedora_vuln_cves;
}
if (os == 'freebsd')
{
  os_vuln_cves = _freebsd_vuln_cves;
  advisories_per_line = 2;
}
if (os == 'ubuntu')
{
  os_vuln_cves = _ubuntu_vuln_cves;
}
if (os == 'vmware')
{
  os_vuln_cves = _vmware_vuln_cves;
}

if (!empty_or_null(os_vuln_cves[version]))
{  
  cve_list = os_vuln_cves[version]['cves'];
  advisory_ids = os_vuln_cves[version]['advisory_ids'];
  cve_split = split(cve_list, sep:', ', keep:0);
  advisory_split = split(advisory_ids, sep:', ', keep:0);
  cves_block = '  ';
  for (i = 0; i < max_index(cve_split); i++)
  {
    terminator = '  ';
    if ((i + 1) % 4 == 0)
    {
      terminator = ',\n  ';
    }
    else if (i == (max_index(cve_split) - 1))
    {
      terminator = '';
    }
    else
    {
      terminator = ', ';
    }
    cves_block += cve_split[i] + terminator;
  }
  advisories_block = '  ';
  for (i = 0; i < max_index(advisory_split); i++)
  {
    terminator = '';
    if ((i + 1) % advisories_per_line == 0)
    {
      terminator = ',\n  ';
    }
    else if (i == (max_index(advisory_split) - 1))
    {
      terminator = '';
    }
    else
    {
      terminator = ', ';
    }
    advisories_block += advisory_split[i] + terminator;
  }

  report += 'Advisories:\n' + advisories_block + '\nCVEs:\n' + cves_block + '\n';
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    extra      : report
  );
}
else
{
  exit(0, "Banner or Host/OS string for OS version not known as vulnerable to CVEs.");
}
