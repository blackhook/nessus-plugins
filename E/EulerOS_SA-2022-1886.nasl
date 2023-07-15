##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162362);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/17");

  script_cve_id(
    "CVE-2020-15157",
    "CVE-2020-15257",
    "CVE-2021-32760",
    "CVE-2021-41103",
    "CVE-2022-24769"
  );

  script_name(english:"EulerOS 2.0 SP5 : docker-engine (EulerOS-SA-2022-1886)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the docker-engine packages installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - In containerd (an industry-standard container runtime) before version 1.2.14 there is a credential leaking
    vulnerability. If a container image manifest in the OCI Image format or Docker Image V2 Schema 2 format
    includes a URL for the location of a specific image layer (otherwise known as a foreign layer), the
    default containerd resolver will follow that URL to attempt to download it. In v1.2.x but not 1.3.0 or
    later, the default containerd resolver will provide its authentication credentials if the server where the
    URL is located presents an HTTP 401 status code along with registry-specific HTTP headers. If an attacker
    publishes a public image with a manifest that directs one of the layers to be fetched from a web server
    they control and they trick a user or system into pulling the image, they can obtain the credentials used
    for pulling that image. In some cases, this may be the user's username and password for the registry. In
    other cases, this may be the credentials attached to the cloud virtual instance which can grant access to
    other cloud resources in the account. The default containerd resolver is used by the cri-containerd plugin
    (which can be used by Kubernetes), the ctr development tool, and other client programs that have
    explicitly linked against it. This vulnerability has been fixed in containerd 1.2.14. containerd 1.3 and
    later are not affected. If you are using containerd 1.3 or later, you are not affected. If you are using
    cri-containerd in the 1.2 series or prior, you should ensure you only pull images from trusted sources.
    Other container runtimes built on top of containerd but not using the default resolver (such as Docker)
    are not affected. (CVE-2020-15157)

  - containerd is an industry-standard container runtime and is available as a daemon for Linux and Windows.
    In containerd before versions 1.3.9 and 1.4.3, the containerd-shim API is improperly exposed to host
    network containers. Access controls for the shim's API socket verified that the connecting process had an
    effective UID of 0, but did not otherwise restrict access to the abstract Unix domain socket. This would
    allow malicious containers running in the same network namespace as the shim, with an effective UID of 0
    but otherwise reduced privileges, to cause new processes to be run with elevated privileges. This
    vulnerability has been fixed in containerd 1.3.9 and 1.4.3. Users should update to these versions as soon
    as they are released. It should be noted that containers started with an old version of containerd-shim
    should be stopped and restarted, as running containers will continue to be vulnerable even after an
    upgrade. If you are not providing the ability for untrusted users to start containers in the same network
    namespace as the shim (typically the 'host' network namespace, for example with docker run --net=host or
    hostNetwork: true in a Kubernetes pod) and run with an effective UID of 0, you are not vulnerable to this
    issue. If you are running containers with a vulnerable configuration, you can deny access to all abstract
    sockets with AppArmor by adding a line similar to deny unix addr=@**, to your policy. It is best practice
    to run containers with a reduced set of privileges, with a non-zero UID, and with isolated namespaces. The
    containerd maintainers strongly advise against sharing namespaces with the host. Reducing the set of
    isolation mechanisms used for a container necessarily increases that container's privilege, regardless of
    what container runtime is used for running that container. (CVE-2020-15257)

  - containerd is a container runtime. A bug was found in containerd versions prior to 1.4.8 and 1.5.4 where
    pulling and extracting a specially-crafted container image can result in Unix file permission changes for
    existing files in the host's filesystem. Changes to file permissions can deny access to the expected owner
    of the file, widen access to others, or set extended bits like setuid, setgid, and sticky. This bug does
    not directly allow files to be read, modified, or executed without an additional cooperating process. This
    bug has been fixed in containerd 1.5.4 and 1.4.8. As a workaround, ensure that users only pull images from
    trusted sources. Linux security modules (LSMs) like SELinux and AppArmor can limit the files potentially
    affected by this bug through policies and profiles that prevent containerd from interacting with specific
    files. (CVE-2021-32760)

  - containerd is an open source container runtime with an emphasis on simplicity, robustness and portability.
    A bug was found in containerd where container root directories and some plugins had insufficiently
    restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and
    execute programs. When containers included executable programs with extended permission bits (such as
    setuid), unprivileged Linux users could discover and execute those programs. When the UID of an
    unprivileged Linux user on the host collided with the file owner or group inside a container, the
    unprivileged Linux user on the host could discover, read, and modify those files. This vulnerability has
    been fixed in containerd 1.4.11 and containerd 1.5.7. Users should update to these version when they are
    released and may restart containers or update directory permissions to mitigate the vulnerability. Users
    unable to update should limit access to the host to trusted users. Update directory permission on
    container bundles directories. (CVE-2021-41103)

  - Moby is an open-source project created by Docker to enable and accelerate software containerization. A bug
    was found in Moby (Docker Engine) prior to version 20.10.14 where containers were incorrectly started with
    non-empty inheritable Linux process capabilities, creating an atypical Linux environment and enabling
    programs with inheritable file capabilities to elevate those capabilities to the permitted set during
    `execve(2)`. Normally, when executable programs have specified permitted file capabilities, otherwise
    unprivileged users and processes can execute those programs and gain the specified file capabilities up to
    the bounding set. Due to this bug, containers which included executable programs with inheritable file
    capabilities allowed otherwise unprivileged users and processes to additionally gain these inheritable
    file capabilities up to the container's bounding set. Containers which use Linux users and groups to
    perform privilege separation inside the container are most directly impacted. This bug did not affect the
    container security sandbox as the inheritable set never contained more capabilities than were included in
    the container's bounding set. This bug has been fixed in Moby (Docker Engine) 20.10.14. Running containers
    should be stopped, deleted, and recreated for the inheritable capabilities to be reset. This fix changes
    Moby (Docker Engine) behavior such that containers are started with a more typical Linux environment. As a
    workaround, the entry point of a container can be modified to use a utility like `capsh(1)` to drop
    inheritable capabilities prior to the primary process starting. (CVE-2022-24769)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1886
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8229852");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker-engine packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41103");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:docker-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:docker-engine-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "docker-engine-18.09.0.101-1.h52.22.9.eulerosv2r7",
  "docker-engine-selinux-18.09.0.101-1.h52.22.9.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker-engine");
}
