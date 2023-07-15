#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176018);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_cve_id("CVE-2022-36109", "CVE-2023-25153", "CVE-2023-25173");

  script_name(english:"EulerOS 2.0 SP10 : docker-engine (EulerOS-SA-2023-1949)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the docker-engine package installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - Moby is an open-source project created by Docker to enable software containerization. A bug was found in
    Moby (Docker Engine) where supplementary groups are not set up properly. If an attacker has direct access
    to a container and manipulates their supplementary group access, they may be able to use supplementary
    group access to bypass primary group restrictions in some cases, potentially gaining access to sensitive
    information or gaining the ability to execute code in that container. This bug is fixed in Moby (Docker
    Engine) 20.10.18. Running containers should be stopped and restarted for the permissions to be fixed. For
    users unable to upgrade, this problem can be worked around by not using the `'USER $USERNAME'` Dockerfile
    instruction. Instead by calling `ENTRYPOINT ['su', '-', 'user']` the supplementary groups will be set up
    properly. (CVE-2022-36109)

  - containerd is an open source container runtime. Before versions 1.6.18 and 1.5.18, when importing an OCI
    image, there was no limit on the number of bytes read for certain files. A maliciously crafted image with
    a large file where a limit was not applied could cause a denial of service. This bug has been fixed in
    containerd 1.6.18 and 1.5.18. Users should update to these versions to resolve the issue. As a workaround,
    ensure that only trusted images are used and that only trusted users have permissions to import images.
    (CVE-2023-25153)

  - containerd is an open source container runtime. A bug was found in containerd prior to versions 1.6.18 and
    1.5.18 where supplementary groups are not set up properly inside a container. If an attacker has direct
    access to a container and manipulates their supplementary group access, they may be able to use
    supplementary group access to bypass primary group restrictions in some cases, potentially gaining access
    to sensitive information or gaining the ability to execute code in that container. Downstream applications
    that use the containerd client library may be affected as well. This bug has been fixed in containerd
    v1.6.18 and v.1.5.18. Users should update to these versions and recreate containers to resolve this issue.
    Users who rely on a downstream application that uses containerd's client library should check that
    application for a separate advisory and instructions. As a workaround, ensure that the `'USER $USERNAME'`
    Dockerfile instruction is not used. Instead, set the container entrypoint to a value similar to
    `ENTRYPOINT ['su', '-', 'user']` to allow `su` to properly set up supplementary groups. (CVE-2023-25173)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1949
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?059202ea");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker-engine packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25173");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:docker-engine-1:18.09.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(10)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP10", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "docker-engine-1:18.09.0-200.h65.34.20.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"10", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker-engine");
}
