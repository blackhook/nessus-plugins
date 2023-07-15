#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0146. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154628);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id("CVE-2020-11078");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : fence-agents Vulnerability (NS-SA-2021-0146)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has fence-agents packages installed that are
affected by a vulnerability:

  - In httplib2 before version 0.18.0, an attacker controlling unescaped part of uri for
    `httplib2.Http.request()` could change request headers and body, send additional hidden requests to same
    server. This vulnerability impacts software that uses httplib2 with uri constructed by string
    concatenation, as opposed to proper urllib building with escaping. This has been fixed in 0.18.0.
    (CVE-2020-11078)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0146");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11078");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL fence-agents packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-lpar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-lpar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'fence-agents-aliyun-4.2.1-41.el7_9.2',
    'fence-agents-all-4.2.1-41.el7_9.2',
    'fence-agents-amt-ws-4.2.1-41.el7_9.2',
    'fence-agents-apc-4.2.1-41.el7_9.2',
    'fence-agents-apc-snmp-4.2.1-41.el7_9.2',
    'fence-agents-aws-4.2.1-41.el7_9.2',
    'fence-agents-azure-arm-4.2.1-41.el7_9.2',
    'fence-agents-bladecenter-4.2.1-41.el7_9.2',
    'fence-agents-brocade-4.2.1-41.el7_9.2',
    'fence-agents-cisco-mds-4.2.1-41.el7_9.2',
    'fence-agents-cisco-ucs-4.2.1-41.el7_9.2',
    'fence-agents-common-4.2.1-41.el7_9.2',
    'fence-agents-compute-4.2.1-41.el7_9.2',
    'fence-agents-drac5-4.2.1-41.el7_9.2',
    'fence-agents-eaton-snmp-4.2.1-41.el7_9.2',
    'fence-agents-emerson-4.2.1-41.el7_9.2',
    'fence-agents-eps-4.2.1-41.el7_9.2',
    'fence-agents-gce-4.2.1-41.el7_9.2',
    'fence-agents-heuristics-ping-4.2.1-41.el7_9.2',
    'fence-agents-hpblade-4.2.1-41.el7_9.2',
    'fence-agents-ibmblade-4.2.1-41.el7_9.2',
    'fence-agents-ifmib-4.2.1-41.el7_9.2',
    'fence-agents-ilo-moonshot-4.2.1-41.el7_9.2',
    'fence-agents-ilo-mp-4.2.1-41.el7_9.2',
    'fence-agents-ilo-ssh-4.2.1-41.el7_9.2',
    'fence-agents-ilo2-4.2.1-41.el7_9.2',
    'fence-agents-intelmodular-4.2.1-41.el7_9.2',
    'fence-agents-ipdu-4.2.1-41.el7_9.2',
    'fence-agents-ipmilan-4.2.1-41.el7_9.2',
    'fence-agents-kdump-4.2.1-41.el7_9.2',
    'fence-agents-lpar-4.2.1-41.el7_9.2',
    'fence-agents-mpath-4.2.1-41.el7_9.2',
    'fence-agents-redfish-4.2.1-41.el7_9.2',
    'fence-agents-rhevm-4.2.1-41.el7_9.2',
    'fence-agents-rsa-4.2.1-41.el7_9.2',
    'fence-agents-rsb-4.2.1-41.el7_9.2',
    'fence-agents-sbd-4.2.1-41.el7_9.2',
    'fence-agents-scsi-4.2.1-41.el7_9.2',
    'fence-agents-virsh-4.2.1-41.el7_9.2',
    'fence-agents-vmware-rest-4.2.1-41.el7_9.2',
    'fence-agents-vmware-soap-4.2.1-41.el7_9.2',
    'fence-agents-wti-4.2.1-41.el7_9.2'
  ],
  'CGSL MAIN 5.05': [
    'fence-agents-aliyun-4.2.1-41.el7_9.2',
    'fence-agents-all-4.2.1-41.el7_9.2',
    'fence-agents-amt-ws-4.2.1-41.el7_9.2',
    'fence-agents-apc-4.2.1-41.el7_9.2',
    'fence-agents-apc-snmp-4.2.1-41.el7_9.2',
    'fence-agents-aws-4.2.1-41.el7_9.2',
    'fence-agents-azure-arm-4.2.1-41.el7_9.2',
    'fence-agents-bladecenter-4.2.1-41.el7_9.2',
    'fence-agents-brocade-4.2.1-41.el7_9.2',
    'fence-agents-cisco-mds-4.2.1-41.el7_9.2',
    'fence-agents-cisco-ucs-4.2.1-41.el7_9.2',
    'fence-agents-common-4.2.1-41.el7_9.2',
    'fence-agents-compute-4.2.1-41.el7_9.2',
    'fence-agents-drac5-4.2.1-41.el7_9.2',
    'fence-agents-eaton-snmp-4.2.1-41.el7_9.2',
    'fence-agents-emerson-4.2.1-41.el7_9.2',
    'fence-agents-eps-4.2.1-41.el7_9.2',
    'fence-agents-gce-4.2.1-41.el7_9.2',
    'fence-agents-heuristics-ping-4.2.1-41.el7_9.2',
    'fence-agents-hpblade-4.2.1-41.el7_9.2',
    'fence-agents-ibmblade-4.2.1-41.el7_9.2',
    'fence-agents-ifmib-4.2.1-41.el7_9.2',
    'fence-agents-ilo-moonshot-4.2.1-41.el7_9.2',
    'fence-agents-ilo-mp-4.2.1-41.el7_9.2',
    'fence-agents-ilo-ssh-4.2.1-41.el7_9.2',
    'fence-agents-ilo2-4.2.1-41.el7_9.2',
    'fence-agents-intelmodular-4.2.1-41.el7_9.2',
    'fence-agents-ipdu-4.2.1-41.el7_9.2',
    'fence-agents-ipmilan-4.2.1-41.el7_9.2',
    'fence-agents-kdump-4.2.1-41.el7_9.2',
    'fence-agents-lpar-4.2.1-41.el7_9.2',
    'fence-agents-mpath-4.2.1-41.el7_9.2',
    'fence-agents-redfish-4.2.1-41.el7_9.2',
    'fence-agents-rhevm-4.2.1-41.el7_9.2',
    'fence-agents-rsa-4.2.1-41.el7_9.2',
    'fence-agents-rsb-4.2.1-41.el7_9.2',
    'fence-agents-sbd-4.2.1-41.el7_9.2',
    'fence-agents-scsi-4.2.1-41.el7_9.2',
    'fence-agents-virsh-4.2.1-41.el7_9.2',
    'fence-agents-vmware-rest-4.2.1-41.el7_9.2',
    'fence-agents-vmware-soap-4.2.1-41.el7_9.2',
    'fence-agents-wti-4.2.1-41.el7_9.2'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fence-agents');
}
