##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5003 and
# CentOS Errata and Security Advisory 2020:5003 respectively.
##

include('compat.inc');

if (description)
{
  script_id(143122);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2020-11078");
  script_xref(name:"RHSA", value:"2020:5003");

  script_name(english:"CentOS 7 : fence-agents (CESA-2020:5003)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2020:5003 advisory.

  - python-httplib2: CRLF injection via an attacker controlled unescaped part of uri for httplib2.Http.request
    function (CVE-2020-11078)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2020-November/035863.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2dd935a5");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/113.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(113);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-aliyun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-azure-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-gce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-lpar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fence-agents-wti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'fence-agents-aliyun-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-all-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-amt-ws-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-apc-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-apc-snmp-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-aws-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-azure-arm-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-bladecenter-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-brocade-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-cisco-mds-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-cisco-ucs-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-common-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-compute-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-drac5-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-eaton-snmp-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-emerson-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-eps-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-gce-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-heuristics-ping-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-hpblade-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-ibmblade-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-ifmib-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-ilo-moonshot-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-ilo-mp-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-ilo-ssh-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-ilo2-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-intelmodular-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-ipdu-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-ipmilan-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-kdump-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-lpar-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-mpath-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-redfish-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-rhevm-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-rsa-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-rsb-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-sbd-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-scsi-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-virsh-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-vmware-rest-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-vmware-soap-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'fence-agents-wti-4.2.1-41.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fence-agents-aliyun / fence-agents-all / fence-agents-amt-ws / etc');
}
