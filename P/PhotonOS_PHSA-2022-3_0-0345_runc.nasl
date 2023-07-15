#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2022-3.0-0345. The text
# itself is copyright (C) VMware, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156579);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2021-43784");

  script_name(english:"Photon OS 3.0: Runc PHSA-2022-3.0-0345");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the runc package has been released.

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
    this bug. (CVE-2021-43784)");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Updates-3.0-345.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:runc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:3.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/PhotonOS/release');
if (isnull(release) || release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (release !~ "^VMware Photon (?:Linux|OS) 3\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 3.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'runc-1.0.0.rc93-9.ph3')) flag++;
if (rpm_check(release:'PhotonOS-3.0', cpu:'x86_64', reference:'runc-doc-1.0.0.rc93-9.ph3')) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'runc');
}
