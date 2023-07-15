#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108590);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/22");

  script_name(english:"Kernel vulnerabilities detected in banner reporting (PCI-DSS check)");
  script_summary(english:"Checks banners for vulnerable kernel levels");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Linux kernel version reported in banners possesses one or more
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A service banner response from the remote host indicates a Linux 
kernel install at a level that may be vulnerable to one or more
non-denial-of-service vulnerabilities.

This plugin only runs when 'Check for PCI-DSS compliance' is enabled
in the scan policy. It does not run if local security checks are
enabled. It runs off of self-reported kernel versions in banners."
  );

  # https://www.cvedetails.com/product/47/Linux-Linux-Kernel.html?vendor_id=33"
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52b202ee");
  script_set_attribute(
    attribute:"solution",
    value:
"Update the version of the Linux kernel running on the system."
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

  script_require_keys("Settings/PCI_DSS");
  script_exclude_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("kernel_cves.inc");
include("lists.inc");

if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);
if (get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are enabled.");

# Check all relevant banner KBs
banners = get_kb_list("*/banner/*");
if (isnull(banners)) exit(0, "Relevant banners not present for this scan.");

global_var ver_compare_regexes = make_array(1, "git(\d+)", -1, "rc(\d+)");
function vcomp ()
{
  var v1 = _FCT_ANON_ARGS[0];
  var v2 = _FCT_ANON_ARGS[1];
  return ver_compare(ver:v1, fix:v2, strict:FALSE, regexes:ver_compare_regexes) < 0;
}

function version_sort ()
{
  var seq = _FCT_ANON_ARGS[0];
  return collib::merge_sort(seq, comparator:@vcomp);
}

# Determine if a kernel version is present in the banners and extract it
port = 0;
version = NULL;
foreach banner_kb (sort(keys(banners)))
{
  banner_value = banners[banner_kb];
  regex = "(?:kernel|linux) (\d+\.\d+\.\d+[^\s]*)";
  kernel_version = pregmatch(string:banner_value, pattern:regex, icase:TRUE);
  if(!isnull(kernel_version))
  {
    version = kernel_version[1];
    #version -= ".EL";
    version = ereg_replace(string:version, pattern:"^(.*?)\.EL(.*)$", replace:"\1\2");
    version = ereg_replace(string:version, pattern:"^(.*?)\.el\d\.(?:x86_64|i\d86)(.*)$", replace:"\1\2");

    # Try and extract port from banner_kb
    portmatch = pregmatch(pattern:"\/(\d+)(?:\/|$)", string:banner_kb);
    if (portmatch)
    {
      port = portmatch[1];
    }
    break;
  }
}

if (isnull(version))
{
  exit(0, "Unable to find kernel version strings in banner(s).");
}

max_score = 0;
report = 'Kernel version: ' + version +
         '\nVulnerabilities associated with unpatched fixes:\n';
foreach check_version (version_sort(keys(_kernel_vuln_cves)))
{
  minver = NULL;
  check_split = split(check_version, sep:'.', keep:FALSE);
  minver = check_split[0];
  if (ver_compare(ver:version, fix:check_version, minver:minver, strict:FALSE, regexes:ver_compare_regexes) < 0)
  {
    version_score = int(_kernel_vuln_cves[check_version]['max_score']);
    version_cves = _kernel_vuln_cves[check_version]['cve_list'];
    if (version_score > max_score)
    {
      max_score = version_score;
    }
    advisory_ids = os_vuln_cves[version]['advisory_ids'];
    cve_split = split(version_cves, sep:', ', keep:0);
    cves_block = '      ';
    for (i = 0; i < max_index(cve_split); i++)
    {
      terminator = ', ';
      if (i == (max_index(cve_split) - 1))
      {
        terminator = '\n';
      }
      else if ((i + 1) % 4 == 0)
      {
        terminator = ',\n      ';
      } 
      else
      {
        terminator = ', ';
      }
      cves_block += cve_split[i] + terminator;
    }
    report += '  - Version ' + check_version + ' fixes:\n' + cves_block;
  }
}

# PCI doesn't care about Low scores
if (max_score > 4)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    extra      : report
  );
}
else
{
  exit(0, "Banner kernel version not known as vulnerable to PCI-appropriate CVEs.");
}
