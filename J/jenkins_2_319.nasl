#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154894);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2021-21685",
    "CVE-2021-21686",
    "CVE-2021-21687",
    "CVE-2021-21688",
    "CVE-2021-21689",
    "CVE-2021-21690",
    "CVE-2021-21691",
    "CVE-2021-21692",
    "CVE-2021-21693",
    "CVE-2021-21694",
    "CVE-2021-21695",
    "CVE-2021-21696",
    "CVE-2021-21697",
    "CVE-2021-21698"
  );
  script_xref(name:"IAVA", value:"2021-A-0551-S");

  script_name(english:"Jenkins LTS < 2.303.3 / Jenkins weekly < 2.319 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its its self-reported version number, the version of Jenkins running on the remote web server is Jenkins
LTS prior to 2.303.3 or Jenkins weekly prior to 2.319. It is, therefore, affected by multiple vulnerabilities:

  - Jenkins 2.318 and earlier, LTS 2.303.2 and earlier does not check agent-to-controller access to create
    parent directories in FilePath#mkdirs. (CVE-2021-21685)

  - File path filters in the agent-to-controller security subsystem of Jenkins 2.318 and earlier, LTS 2.303.2
    and earlier do not canonicalize paths, allowing operations to follow symbolic links to outside allowed
    directories. (CVE-2021-21686)

  - Jenkins 2.318 and earlier, LTS 2.303.2 and earlier does not check agent-to-controller access to create
    symbolic links when unarchiving a symbolic link in FilePath#untar. (CVE-2021-21687)

  - The agent-to-controller security check FilePath#reading(FileVisitor) in Jenkins 2.318 and earlier, LTS
    2.303.2 and earlier does not reject any operations, allowing users to have unrestricted read access using
    certain operations (creating archives, FilePath#copyRecursiveTo). (CVE-2021-21688)

  - FilePath#unzip and FilePath#untar were not subject to any agent-to-controller access control in Jenkins
    2.318 and earlier, LTS 2.303.2 and earlier. (CVE-2021-21689)

  - Agent processes are able to completely bypass file path filtering by wrapping the file operation in an
    agent file path in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier. (CVE-2021-21690)

  - Creating symbolic links is possible without the 'symlink' agent-to-controller access control permission in
    Jenkins 2.318 and earlier, LTS 2.303.2 and earlier. (CVE-2021-21691)

  - FilePath#renameTo and FilePath#moveAllChildrenTo in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier
    only check 'read' agent-to-controller access permission on the source path, instead of 'delete'.
    (CVE-2021-21692)

  - When creating temporary files, agent-to-controller access to create those files is only checked after
    they've been created in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier. (CVE-2021-21693)

  - FilePath#toURI, FilePath#hasSymlink, FilePath#absolutize, FilePath#isDescendant, and
    FilePath#get*DiskSpace do not check any permissions in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier.
    (CVE-2021-21694)

  - FilePath#listFiles lists files outside directories that agents are allowed to access when following
    symbolic links in Jenkins 2.318 and earlier, LTS 2.303.2 and earlier. (CVE-2021-21695)

  - Jenkins 2.318 and earlier, LTS 2.303.2 and earlier does not limit agent read/write access to the libs/
    directory inside build directories when using the FilePath APIs, allowing attackers in control of agent
    processes to replace the code of a trusted library with a modified variant. This results in unsandboxed
    code execution in the Jenkins controller process. (CVE-2021-21696)

  - Jenkins 2.318 and earlier, LTS 2.303.2 and earlier allows any agent to read and write the contents of any
    build directory stored in Jenkins with very few restrictions. (CVE-2021-21697)

  - Jenkins Subversion Plugin 2.15.0 and earlier does not restrict the name of a file when looking up a
    subversion key file on the controller from an agent. (CVE-2021-21698)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2021-11-04");
  script_set_attribute(attribute:"solution", value:
"Upgrade Jenkins weekly to version 2.319 or later or Jenkins LTS to version 2.303.3 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21696");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Jenkins');

var constraints = [
  { 'max_version' : '2.318', 'fixed_version' : '2.319', 'edition' : 'Open Source' },
  { 'max_version' : '2.303.2', 'fixed_version' : '2.303.3', 'edition' : 'Open Source LTS' }
];

vcf::jenkins::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
