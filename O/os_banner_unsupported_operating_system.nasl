#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122403);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/06");

  script_name(english:"Operating System Unsupported Version Detection in banner reporting (PCI-DSS check)");
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
"A service banner response from the remote host indicates an
operating system install at a level that indicates the operating
system running on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

This plugin only runs when 'Check for PCI-DSS compliance' is enabled
in the scan policy. It does not run if local security checks are
enabled. It runs off of self-reported OS versions in banners and
fingerprinting."
  );

  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to a version of the operating system that is currently
supported."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default unsupported software score.");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl", "os_fingerprint.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Host/local_checks_enabled", "Host/OS/obsolete");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("os_eol.inc");
include("lists.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);
if (get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are enabled.");
if (get_kb_item("Host/OS/obsolete")) exit(0, "unsupported_operating_system.nasl has already successfully run.");

# Check all relevant banner KBs
banners = get_kb_list("*/banner/*");
host_os = get_kb_item("Host/OS");
if (isnull(banners)) exit(0, "Relevant banners are not present for this scan.");

# Determine if a supported OS version is present in the banners and extract it
port = 0;
version = NULL;
os = NULL;
regex_list = [
  "(CentOS) release (\d+(?:\.\d+)*)",
  "(FreeBSD)(?:\s*|\/)(\d+\.\d+)-RELEASE",
  "(VMware) ESX Server (\di?) (\d.\d)",
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

if (isnull(version) || isnull(os))
{
  exit(0, "Unable to find OS version strings in banner(s).");
}

report = 'OS version: ' + os + ' ' + version +
         '\nVulnerabilities potentially exist associated with potentially\n' + 
         'unpatched fixes.\n';
os_copy = os;
os = tolower(os);

if (os == 'centos')
{
  eol = _centos_eol;
  version_split = split(version, sep:'.', keep:0);
  version = version_split[0];
}
if (os == 'fedora')
{
  eol = _fedora_eol;
}
if (os == 'freebsd')
{
  eol = _freebsd_eol;
}
if (os == 'ubuntu')
{
  eol = _ubuntu_eol;
}
if (os == 'vmware')
{
  eol = _vmware_eol;
}

if (isnull(eol[version]))
{
  exit(0, "The remote host's operating system " + os_copy + " version " + version + " is still supported.");
}
else
{
  eol_date = eol[version];
  supported_levels = _latest_supported[os_copy];
  report =  'Operating System:    ' + os_copy + '\n';
  report +=  'Version:             ' + version + '\n';
  report += 'End of support date: ' + eol_date + '\n';
  report += 'Currently supported OS versions: ' + supported_levels + '\n';
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    extra      : report
  );
}
