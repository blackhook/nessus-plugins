#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172394);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id(
    "CVE-2023-24998",
    "CVE-2023-27898",
    "CVE-2023-27899",
    "CVE-2023-27900",
    "CVE-2023-27901",
    "CVE-2023-27902",
    "CVE-2023-27903",
    "CVE-2023-27904",
    "CVE-2023-27905"
  );
  script_xref(name:"IAVA", value:"2023-A-0127-S");

  script_name(english:"Jenkins LTS < 2.375.4 / Jenkins weekly < 2.394 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.375.4 or Jenkins weekly prior to 2.394. It is, therefore, affected by multiple vulnerabilities:

  - Apache Commons FileUpload before 1.5 does not limit the number of request parts to be processed resulting
    in the possibility of an attacker triggering a DoS with a malicious upload or series of uploads. Note
    that, like all of the file upload limits, the new configuration option (FileUploadBase#setFileCountMax) is
    not enabled by default and must be explicitly configured. (CVE-2023-24998)

  - High Jenkins 2.270 through 2.393 (both inclusive), LTS 2.277.1 through 2.375.3 (both inclusive) does not
    escape the Jenkins version a plugin depends on when rendering the error message stating its
    incompatibility with the current version of Jenkins in the plugin manager. This results in a stored cross-
    site scripting (XSS) vulnerability exploitable by attackers able to provide plugins to the configured
    update sites and have this message shown by Jenkins instances. Exploitation does not require the
    manipulated plugin to be installed. Jenkins 2.394, LTS 2.375.4, and LTS 2.387.1 escapes the Jenkins
    version a plugin depends on when rendering the error message stating its incompatibility with the current
    version of Jenkins. Due to how Jenkins community update sites serve plugin metadata based on the reported
    Jenkins core version, it is unlikely that a reasonably up to date Jenkins instance shows the vulnerable
    error message in the plugin manager at all. At least one of the following conditions needs to be met: The
    Jenkins version used is older than about 13 months (before 2.333 or LTS 2.319.2 as of publication of this
    advisory), as all more recent releases of Jenkins receive update site metadata that only includes
    compatible versions of plugins. Jenkins has been downgraded from a newer version, and no updated update
    site metadata has been requested since, so Jenkins will still display available plugins compatible with
    the previously newer version of Jenkins. Custom update site URLs (i.e., not
    https://updates.jenkins.io/update-center.json) are configured, and those update sites behave differently.
    We expect that most of these will host a fairly small set of vetted plugins (e.g., an organization's
    approved or internal plugins), preventing exploitation through their restrictive inclusion process.
    Jenkins community update sites no longer publish plugin releases with invalid Jenkins core dependencies
    since 2023-02-15. This prevents exploitation through those update sites even on versions of Jenkins older
    than 13 months. Additionally, the Jenkins security team has confirmed that no plugin release with a core
    dependency manipulated to exploit this vulnerability has ever been published by the Jenkins project.
    (CVE-2023-27898)

  - High Jenkins creates a temporary file when a plugin is uploaded from an administrator's computer. Jenkins
    2.393 and earlier, LTS 2.375.3 and earlier creates this temporary file in the system temporary directory
    with the default permissions for newly created files. If these permissions are overly permissive, they may
    allow attackers with access to the Jenkins controller file system to read and write the file before it is
    installed in Jenkins, potentially resulting in arbitrary code execution. This vulnerability only affects
    operating systems using a shared temporary directory for all users (typically Linux). Additionally, the
    default permissions for newly created files generally only allows attackers to read the temporary file.
    Jenkins 2.394, LTS 2.375.4, and LTS 2.387.1 creates the temporary file with more restrictive permissions.
    As a workaround, you can set a different path as your default temporary directory using the Java system
    property java.io.tmpdir, if you're concerned about this issue but unable to immediately update Jenkins.
    (CVE-2023-27899)

  - Medium Jenkins 2.393 and earlier, LTS 2.375.3 and earlier is affected by the Apache Commons FileUpload
    library's vulnerability CVE-2023-24998. This library is used to process uploaded files via the Stapler web
    framework (usually through StaplerRequest#getFile) and MultipartFormDataParser in Jenkins. This allows
    attackers to cause a denial of service (DoS) by sending crafted requests to HTTP endpoints processing file
    uploads. Jenkins 2.394, LTS 2.375.4, and LTS 2.387.1 limits the number of request parts to be processed to
    1000. Specific endpoints receiving only simple form submissions have a lower limit. While the Apache
    Commons FileUpload dependency has been updated previously in the 2.392 weekly release, the Jenkins-
    specific changes in 2.394 are necessary for Jenkins to be protected. Some Jenkins forms can be very
    complex, and these limits apply to all fields and not just fields representing uploaded files. As a
    result, legitimate submissions of complex forms that include (possible) file uploads may be affected by
    these limits. If that happens, these limits can be changed by setting the Java system properties
    hudson.util.MultipartFormDataParser.FILEUPLOAD_MAX_FILES and
    org.kohsuke.stapler.RequestImpl.FILEUPLOAD_MAX_FILES to a bigger value, or to -1 to completely disable
    them. These releases of Jenkins also introduce additional Java system properties that can be set to
    restrict request sizes: hudson.util.MultipartFormDataParser.FILEUPLOAD_MAX_FILE_SIZE and
    org.kohsuke.stapler.RequestImpl.FILEUPLOAD_MAX_FILE_SIZE allow limiting the size (in bytes) of individual
    fields that can be processed in one multipart/form-data request.
    hudson.util.MultipartFormDataParser.FILEUPLOAD_MAX_SIZE and
    org.kohsuke.stapler.RequestImpl.FILEUPLOAD_MAX_SIZE allow limiting the total request size (in bytes) that
    can be processed in one multipart/form-data request. By default, Jenkins does not set these size limits.
    Setting these system properties can offer additional protection, but comes at a greater risk of impacting
    legitimate use (e.g., when uploading huge file parameters). (CVE-2023-27900, CVE-2023-27901)

  - Medium Jenkins uses temporary directories adjacent to workspace directories, usually with the @tmp name
    suffix, to store temporary files related to the build. In pipelines, these temporary directories are
    adjacent to the current working directory when operating in a subdirectory of the automatically allocated
    workspace. Jenkins-controlled processes, like SCMs, may store credentials in these directories. Jenkins
    2.393 and earlier, LTS 2.375.3 and earlier shows these temporary directories when viewing job workspaces,
    which allows attackers with Item/Workspace permission to access their contents. Jenkins 2.394, LTS
    2.375.4, and LTS 2.387.1 does not list these temporary directories in job workspaces. As a workaround, do
    not grant Item/Workspace permission to users who lack Item/Configure permission, if you're concerned about
    this issue but unable to immediately update Jenkins. The Java system property
    hudson.model.DirectoryBrowserSupport.allowTmpEscape can be set to true to restore the previous behavior.
    (CVE-2023-27902)

  - Low When triggering a build from the Jenkins CLI, Jenkins creates a temporary file on the controller if a
    file parameter is provided through the CLI's standard input. Jenkins 2.393 and earlier, LTS 2.375.3 and
    earlier creates this temporary file in the default temporary directory with the default permissions for
    newly created files. If these permissions are overly permissive, they may allow attackers with access to
    the Jenkins controller file system to read and write the file before it is used in the build. This
    vulnerability only affects operating systems using a shared temporary directory for all users (typically
    Linux). Additionally, the default permissions for newly created files generally only allows attackers to
    read the temporary file. Jenkins 2.394, LTS 2.375.4, and LTS 2.387.1 creates the temporary file with more
    restrictive permissions. As a workaround, you can set a different path as your default temporary directory
    using the Java system property java.io.tmpdir, if you're concerned about this issue but unable to
    immediately update Jenkins. (CVE-2023-27903)

  - Low Jenkins 2.393 and earlier, LTS 2.375.3 and earlier prints an error stack trace on agent-related pages
    when agent connections are broken. This stack trace may contain information about Jenkins configuration
    that is otherwise inaccessible to attackers. Jenkins 2.394, LTS 2.375.4, and LTS 2.387.1 does not display
    error stack traces when agent connections are broken. (CVE-2023-27904)

  - Medium update-center2 is the tool used to generate the Jenkins update sites hosted on updates.jenkins.io.
    While it is designed for use by the Jenkins project for this purpose, others may be using it to operate
    their own self-hosted update sites. update-center2 3.13 and 3.14 renders the required Jenkins core version
    on plugin download index pages (pages like this). This version is taken from plugin metadata without being
    sanitized. This results in a stored cross-site scripting (XSS) vulnerability exploitable by attackers able
    to provide a plugin for hosting. The following preconditions must both be satisfied for this to be
    exploitable in a self-hosted update-center2: The generation of download pages needs to be enabled (i.e.,
    the --download-links-directory argument needs to be set). A custom download page template must be used
    (--index-template-url argument), and the template used must not prevent JavaScript execution through
    Content-Security-Policy. The default template prevents exploitation by declaring a restrictive Content-
    Security-Policy. update-center2 3.15 filters out plugin releases with invalid Jenkins core dependencies.
    Administrators hosting their own update sites using update-center2 or a fork thereof are advised to update
    it, or integrate the commit 091ef999. This change has been deployed to Jenkins community update sites on
    2023-02-15. The Jenkins project has distributed a single plugin release, that exploited this vulnerability
    in a harmless way to demonstrate the issue, for two hours on 2023-01-16. No other plugin releases that
    exploit this vulnerability have been published. (CVE-2023-27905)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2023-03-08");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.394 or later, or Jenkins LTS to version 2.375.4 or 2.387.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27899");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var constraints = [
  { 'max_version' : '2.393', 'fixed_version' : '2.394', 'edition' : 'Open Source' },
  { 'max_version' : '2.375.3', 'fixed_version' : '2.375.4', 'fixed_display' : '2.375.4 or 2.387.1', 'edition' : 'Open Source LTS' }
];

var app_info = vcf::combined_get_app_info(app:'Jenkins');

vcf::jenkins::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
