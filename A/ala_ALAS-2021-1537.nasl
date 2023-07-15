#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1537.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153861);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/08");

  script_cve_id("CVE-2021-41089", "CVE-2021-41091", "CVE-2021-41092");
  script_xref(name:"ALAS", value:"2021-1537");

  script_name(english:"Amazon Linux AMI : docker (ALAS-2021-1537)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of docker installed on the remote host is prior to 20.10.7-3.71. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2021-1537 advisory.

  - Moby is an open-source project created by Docker to enable software containerization. A bug was found in
    Moby (Docker Engine) where attempting to copy files using `docker cp` into a specially-crafted container
    can result in Unix file permission changes for existing files in the hosts filesystem, widening access
    to others. This bug does not directly allow files to be read, modified, or executed without an additional
    cooperating process. This bug has been fixed in Moby (Docker Engine) 20.10.9. Users should update to this
    version as soon as possible. Running containers do not need to be restarted. (CVE-2021-41089)

  - Moby is an open-source project created by Docker to enable software containerization. A bug was found in
    Moby (Docker Engine) where the data directory (typically `/var/lib/docker`) contained subdirectories with
    insufficiently restricted permissions, allowing otherwise unprivileged Linux users to traverse directory
    contents and execute programs. When containers included executable programs with extended permission bits
    (such as `setuid`), unprivileged Linux users could discover and execute those programs. When the UID of an
    unprivileged Linux user on the host collided with the file owner or group inside a container, the
    unprivileged Linux user on the host could discover, read, and modify those files. This bug has been fixed
    in Moby (Docker Engine) 20.10.9. Users should update to this version as soon as possible. Running
    containers should be stopped and restarted for the permissions to be fixed. For users unable to upgrade
    limit access to the host to trusted users. Limit access to host volumes to trusted containers.
    (CVE-2021-41091)

  - Docker CLI is the command line interface for the docker container runtime. A bug was found in the Docker
    CLI where running `docker login my-private-registry.example.com` with a misconfigured configuration file
    (typically `~/.docker/config.json`) listing a `credsStore` or `credHelpers` that could not be executed
    would result in any provided credentials being sent to `registry-1.docker.io` rather than the intended
    private registry. This bug has been fixed in Docker CLI 20.10.9. Users should update to this version as
    soon as possible. For users unable to update ensure that any configured credsStore or credHelpers entries
    in the configuration file reference an installed credential helper that is executable and on the PATH.
    (CVE-2021-41092)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1537.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-41089");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-41091");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-41092");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update docker' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41092");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
var os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'docker-20.10.7-3.71.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'docker-debuginfo-20.10.7-3.71.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker / docker-debuginfo");
}