#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0214. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131417);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2019-10153");
  script_bugtraq_id(108563);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : fence-agents Vulnerability (NS-SA-2019-0214)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has fence-agents packages installed that are
affected by a vulnerability:

  - A flaw was discovered in fence-agents, prior to version
    4.3.4, where using non-ASCII characters in a guest VM's
    comment or other fields would cause fence_rhevm to exit
    with an exception. In cluster environments, this could
    lead to preventing automated recovery or otherwise
    denying service to clusters of which that VM is a
    member. (CVE-2019-10153)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0214");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL fence-agents packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "fence-agents-aliyun-4.2.1-24.el7",
    "fence-agents-all-4.2.1-24.el7",
    "fence-agents-amt-ws-4.2.1-24.el7",
    "fence-agents-apc-4.2.1-24.el7",
    "fence-agents-apc-snmp-4.2.1-24.el7",
    "fence-agents-aws-4.2.1-24.el7",
    "fence-agents-azure-arm-4.2.1-24.el7",
    "fence-agents-bladecenter-4.2.1-24.el7",
    "fence-agents-brocade-4.2.1-24.el7",
    "fence-agents-cisco-mds-4.2.1-24.el7",
    "fence-agents-cisco-ucs-4.2.1-24.el7",
    "fence-agents-common-4.2.1-24.el7",
    "fence-agents-compute-4.2.1-24.el7",
    "fence-agents-debuginfo-4.2.1-24.el7",
    "fence-agents-drac5-4.2.1-24.el7",
    "fence-agents-eaton-snmp-4.2.1-24.el7",
    "fence-agents-emerson-4.2.1-24.el7",
    "fence-agents-eps-4.2.1-24.el7",
    "fence-agents-gce-4.2.1-24.el7",
    "fence-agents-heuristics-ping-4.2.1-24.el7",
    "fence-agents-hpblade-4.2.1-24.el7",
    "fence-agents-ibmblade-4.2.1-24.el7",
    "fence-agents-ifmib-4.2.1-24.el7",
    "fence-agents-ilo-moonshot-4.2.1-24.el7",
    "fence-agents-ilo-mp-4.2.1-24.el7",
    "fence-agents-ilo-ssh-4.2.1-24.el7",
    "fence-agents-ilo2-4.2.1-24.el7",
    "fence-agents-intelmodular-4.2.1-24.el7",
    "fence-agents-ipdu-4.2.1-24.el7",
    "fence-agents-ipmilan-4.2.1-24.el7",
    "fence-agents-kdump-4.2.1-24.el7",
    "fence-agents-mpath-4.2.1-24.el7",
    "fence-agents-redfish-4.2.1-24.el7",
    "fence-agents-rhevm-4.2.1-24.el7",
    "fence-agents-rsa-4.2.1-24.el7",
    "fence-agents-rsb-4.2.1-24.el7",
    "fence-agents-sbd-4.2.1-24.el7",
    "fence-agents-scsi-4.2.1-24.el7",
    "fence-agents-virsh-4.2.1-24.el7",
    "fence-agents-vmware-rest-4.2.1-24.el7",
    "fence-agents-vmware-soap-4.2.1-24.el7",
    "fence-agents-wti-4.2.1-24.el7"
  ],
  "CGSL MAIN 5.04": [
    "fence-agents-aliyun-4.2.1-24.el7",
    "fence-agents-all-4.2.1-24.el7",
    "fence-agents-amt-ws-4.2.1-24.el7",
    "fence-agents-apc-4.2.1-24.el7",
    "fence-agents-apc-snmp-4.2.1-24.el7",
    "fence-agents-aws-4.2.1-24.el7",
    "fence-agents-azure-arm-4.2.1-24.el7",
    "fence-agents-bladecenter-4.2.1-24.el7",
    "fence-agents-brocade-4.2.1-24.el7",
    "fence-agents-cisco-mds-4.2.1-24.el7",
    "fence-agents-cisco-ucs-4.2.1-24.el7",
    "fence-agents-common-4.2.1-24.el7",
    "fence-agents-compute-4.2.1-24.el7",
    "fence-agents-debuginfo-4.2.1-24.el7",
    "fence-agents-drac5-4.2.1-24.el7",
    "fence-agents-eaton-snmp-4.2.1-24.el7",
    "fence-agents-emerson-4.2.1-24.el7",
    "fence-agents-eps-4.2.1-24.el7",
    "fence-agents-gce-4.2.1-24.el7",
    "fence-agents-heuristics-ping-4.2.1-24.el7",
    "fence-agents-hpblade-4.2.1-24.el7",
    "fence-agents-ibmblade-4.2.1-24.el7",
    "fence-agents-ifmib-4.2.1-24.el7",
    "fence-agents-ilo-moonshot-4.2.1-24.el7",
    "fence-agents-ilo-mp-4.2.1-24.el7",
    "fence-agents-ilo-ssh-4.2.1-24.el7",
    "fence-agents-ilo2-4.2.1-24.el7",
    "fence-agents-intelmodular-4.2.1-24.el7",
    "fence-agents-ipdu-4.2.1-24.el7",
    "fence-agents-ipmilan-4.2.1-24.el7",
    "fence-agents-kdump-4.2.1-24.el7",
    "fence-agents-mpath-4.2.1-24.el7",
    "fence-agents-redfish-4.2.1-24.el7",
    "fence-agents-rhevm-4.2.1-24.el7",
    "fence-agents-rsa-4.2.1-24.el7",
    "fence-agents-rsb-4.2.1-24.el7",
    "fence-agents-sbd-4.2.1-24.el7",
    "fence-agents-scsi-4.2.1-24.el7",
    "fence-agents-virsh-4.2.1-24.el7",
    "fence-agents-vmware-rest-4.2.1-24.el7",
    "fence-agents-vmware-soap-4.2.1-24.el7",
    "fence-agents-wti-4.2.1-24.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fence-agents");
}
