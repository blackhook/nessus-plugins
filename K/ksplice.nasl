#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65047);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/11 17:29:26");

  script_name(english:"KSplice : Installed Patches");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is using KSplice to maintain the OS kernel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Ksplice is being used to maintain the remote host's operating system
kernel without requiring reboots."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ksplice.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ksplice.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Check for ksplice status data
status = get_one_kb_item("Host/ksplice/status");
status = ereg_replace(pattern:"\s+$", replace:"", string:status);
cves = make_list();
if (!empty_or_null(status))
{
  previous_line = "";
  installed_section = 0;
  status_split = split(status, sep:'\n', keep:FALSE);
  foreach line (status_split)
  {
    if (empty_or_null(line)) continue;
    if (preg(string:line, pattern:"^\s*Installed:\s*$")) installed_section = 1;
    if (!installed_section) continue;
    if (!empty(previous_line)) line = previous_line + line;
    if (preg(string:line, pattern:"}\s*$"))
    {
      previous_line = "";
      line_split = split(line, sep:' ', keep:FALSE);
      for (m=0;m<max_index(line_split);m++)
      {
        word = line_split[m];
        cve_match = pregmatch(string:word, pattern:"(CVE-\d{4}-\d{4,})");
        if (!empty_or_null(cve_match) && !empty_or_null(cve_match[1]))
        {
          cves = make_list(cves, cve_match[1]);
        }
      }
    }
    else
    {
      previous_line += line;
    }
  }
  # If the status file exists but no updates have been installed, write a dummy CVE to ensure 
  # Host/ksplice/kernel-cves can be written so that KSplice checks execute correctly.
  if (empty_or_null(cves)) {
    cves = make_list("NONE");
  }
}
if (!empty_or_null(cves)) {
  cves = collib::cve_sort(cves);
  cve_list = join(cves, sep:",");
  replace_kb_item(name:"Host/ksplice/kernel-cves", value:cve_list);
}


if (!get_kb_item("Host/uptrack-uname-a") && !cve_list) audit(AUDIT_NOT_INST, "KSplice");

# if the file /etc/uptrack/disable exists then ksplice/uptrack is disabled
if (get_kb_item("Host/uptrack-disable-file")) exit(0, "Ksplice is installed but is not currently being used.");

report = "";
if (get_kb_item("Host/uptrack-show-installed"))
{
  installed_patches = get_kb_item("Host/uptrack-show-installed");
  installed_patches = ereg_replace(pattern:"\nEffective kernel version.*", replace:"", string:installed_patches);
  report += installed_patches;
}
if (report != "") report += '\n' + '\n';
if (!empty_or_null(cve_list))
{
  report += 'Kernel CVEs determined to be patched through Uptrack or KSplice:\n';
  cves_block = '  ';
  for (i = 0; i < max_index(cves); i++)
  {
    terminator = '  ';
    if (i == (max_index(cves) - 1))
    {
      terminator = '';
    }
    else if ((i + 1) % 4 == 0)
    {
      terminator = ',\n  ';
    }
    else
    {
      terminator = ', ';
    }
    cves_block += cves[i] + terminator;
  }
  report += cves_block;
}
if (report != "") report += '\n' + '\n';
if (get_kb_item("Host/uptrack-show-available"))
{
  available_patches = get_kb_item("Host/uptrack-show-available");
  available_patches = ereg_replace(pattern:"\nEffective kernel version.*", replace:"", string:available_patches);
  report += available_patches;
}
if (report_verbosity > 0) security_note(port:0, extra:report);
else security_note(0);
