##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-5003.
##

include('compat.inc');

if (description)
{
  script_id(142790);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id("CVE-2020-11078");

  script_name(english:"Oracle Linux 7 : fence-agents (ELSA-2020-5003)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2020-5003 advisory.

  - In httplib2 before version 0.18.0, an attacker controlling unescaped part of uri for
    `httplib2.Http.request()` could change request headers and body, send additional hidden requests to same
    server. This vulnerability impacts software that uses httplib2 with uri constructed by string
    concatenation, as opposed to proper urllib building with escaping. This has been fixed in 0.18.0.
    (CVE-2020-11078)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-5003.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-amt-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-apc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-apc-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-bladecenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-cisco-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-cisco-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-drac5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-eaton-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-emerson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-heuristics-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-hpblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-ibmblade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-ifmib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-ilo-moonshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-ilo-mp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-ilo-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-ilo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-intelmodular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-ipdu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-ipmilan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-lpar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-redfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-rsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-sbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-virsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-vmware-rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-vmware-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:fence-agents-wti");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

pkgs = [
    {'reference':'fence-agents-all-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-amt-ws-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-apc-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-apc-snmp-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-bladecenter-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-brocade-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-cisco-mds-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-cisco-ucs-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-common-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-compute-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-drac5-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-eaton-snmp-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-emerson-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-eps-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-heuristics-ping-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-hpblade-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-ibmblade-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-ifmib-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-ilo-moonshot-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-ilo-mp-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-ilo-ssh-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-ilo2-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-intelmodular-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-ipdu-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-ipmilan-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-kdump-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-lpar-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-mpath-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-redfish-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-rhevm-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-rsa-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-rsb-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-sbd-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-scsi-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-virsh-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-vmware-rest-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-vmware-soap-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'},
    {'reference':'fence-agents-wti-4.2.1-41.el7_9.2', 'cpu':'x86_64', 'release':'7'}
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
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fence-agents-all / fence-agents-amt-ws / fence-agents-apc / etc');
}