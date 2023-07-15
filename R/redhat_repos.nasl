#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149983);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/03");

  script_name(english:"Red Hat Enterprise Linux : Enabled Official Repositories");
  script_summary(english:"Checks .repo file output repos against a list of official RHEL repos");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is using one or more official Red Hat repositories to install packages."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is using one or more official Red Hat repositories to install packages.
These repositories will be used in conjunction with Red Hat OS package level assessment security advisories to determine whether or not relevant repositories are installed before checking package versions for vulnerable ranges."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/metrics/repository-to-cpe.json");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("lists.inc");
include("misc_func.inc");
include("rhel.inc");
include("rhel_repos.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Check for repo list data
var host_repo_details = get_kb_list("Host/RedHat/repo-list/*");
if (empty_or_null(host_repo_details)) audit(AUDIT_NOT_INST, "a RHEL repository or repository relative URL");

var report = '';
var host_repo_labels = [];
var host_repo_urls = [];
var valid_repo_urls = [];
var valid_repos = [];

foreach var repo_detail (keys(host_repo_details))
{
  if (preg(pattern:"\/relative-url$", string:repo_detail)) {
    # repo_detail is a repository relative URL rather than a repository label.
    append_element(var:host_repo_urls, value:host_repo_details[repo_detail]);
  } else {
    # Replace Host/RedHat/repo-list/ so we are just left with the repo label.
    repo_detail = ereg_replace(pattern:"Host\/RedHat\/repo-list\/", replace:"", string:repo_detail);
    append_element(var:host_repo_labels, value:repo_detail);
  }
}
# No repository labels or relative URLs were found during the scan.
if (empty_or_null(host_repo_labels) && empty_or_null(host_repo_urls)) audit(AUDIT_NOT_INST, "a RHEL repository or repository relative URL");

# Check for repo label data first so it at least writes the valid-repos KB
if (!(empty_or_null(host_repo_labels))) {
  host_repo_labels = sort(host_repo_labels);
  var repo_block = '';
  for (var m=0; m < max_index(host_repo_labels); m++) {
    repo_block += '  ' + host_repo_labels[m] + '\n';
  }

  # Determine if we have any valid repository labels
  valid_repos = sort(collib::intersection(host_repo_labels, RHEL_REPO_LABELS));

  var valid_block = '';
  if (!(empty_or_null(valid_repos))) {
    for (m = 0; m < max_index(valid_repos); m++) {
      valid_block += '  ' + valid_repos[m] + '\n';
    }
    var repo_join = serialize(valid_repos); 
    replace_kb_item(name:"Host/RedHat/valid-repos", value:repo_join);
  } else {
    valid_block = '  None';
  }
  # Do not report the discovered and valid RHEL repo labels. They are not used anymore.
}

# Check for repo relative URL data
if ((empty_or_null(host_repo_urls))) audit(AUDIT_NOT_INST, "a repository relative URL");

host_repo_urls = sort(host_repo_urls);
var repo_url_block = '';
for (var m=0; m < max_index(host_repo_urls); m++) {
  repo_url_block += '  ' + host_repo_urls[m] + '\n';
}
# Determine if we have any valid repository relative URLs
var valid_url_block = '';
valid_repo_urls = sort(collib::intersection(host_repo_urls, RHEL_RELATIVE_URLS));
if (!(empty_or_null(valid_repo_urls))) {
  var repo_url_join = serialize(valid_repo_urls);
  replace_kb_item(name:"Host/RedHat/valid-repo-relative-urls", value:repo_url_join);
  for (m = 0; m < max_index(valid_repo_urls); m++) {
    valid_url_block += '  ' + valid_repo_urls[m] + '\n';
  }
} else {
  valid_url_block = '  None\n';
}

# Check if no valid repository relative URLs were found.
if (empty_or_null(valid_repo_urls)) audit(AUDIT_NOT_INST, "a valid repository relative URL");

report += 'Red Hat Repo Relative URLs found to be enabled:\n' + repo_url_block + '\nValid Red Hat Repo Relative URLs found to be enabled:\n' + valid_url_block + '\n';

security_report_v4(
  port       : 0,
  severity   : SECURITY_NOTE,
  extra      : report
);
