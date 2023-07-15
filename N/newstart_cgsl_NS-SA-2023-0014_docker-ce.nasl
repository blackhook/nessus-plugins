#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0014. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174054);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id("CVE-2021-41089", "CVE-2021-41091", "CVE-2021-43784");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : docker-ce Multiple Vulnerabilities (NS-SA-2023-0014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has docker-ce packages installed that are affected
by multiple vulnerabilities:

  - Moby is an open-source project created by Docker to enable software containerization. A bug was found in
    Moby (Docker Engine) where attempting to copy files using `docker cp` into a specially-crafted container
    can result in Unix file permission changes for existing files in the host's filesystem, widening access to
    others. This bug does not directly allow files to be read, modified, or executed without an additional
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

  - runc is a CLI tool for spawning and running containers on Linux according to the OCI specification. In
    runc, netlink is used internally as a serialization system for specifying the relevant container
    configuration to the `C` portion of the code (responsible for the based namespace setup of containers). In
    all versions of runc prior to 1.0.3, the encoder did not handle the possibility of an integer overflow in
    the 16-bit length field for the byte array attribute type, meaning that a large enough malicious byte
    array attribute could result in the length overflowing and the attribute contents being parsed as netlink
    messages for container configuration. This vulnerability requires the attacker to have some control over
    the configuration of the container and would allow the attacker to bypass the namespace restrictions of
    the container by simply adding their own netlink payload which disables all namespaces. The main users
    impacted are those who allow untrusted images with untrusted configurations to run on their machines (such
    as with shared cloud infrastructure). runc version 1.0.3 contains a fix for this bug. As a workaround, one
    may try disallowing untrusted namespace paths from your container. It should be noted that untrusted
    namespace paths would allow the attacker to disable namespace protections entirely even in the absence of
    this bug. (CVE-2021-43784)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0014");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-41089");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-41091");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-43784");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL docker-ce packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43784");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-41091");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:docker-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:docker-ce-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:docker-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:docker-ce-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.05" &&
    os_release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'docker-ce-17.03.3-1.el7.2210280621gitde6da37',
    'docker-ce-debuginfo-17.03.3-1.el7.2210280621gitde6da37'
  ],
  'CGSL MAIN 5.05': [
    'docker-ce-17.03.3-1.el7.2210280621gitde6da37',
    'docker-ce-debuginfo-17.03.3-1.el7.2210280621gitde6da37'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'docker-ce');
}
