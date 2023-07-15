#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14729-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150579);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2014-0191",
    "CVE-2019-19956",
    "CVE-2019-20388",
    "CVE-2020-7595",
    "CVE-2020-24977",
    "CVE-2021-3516",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14729-1");
  script_xref(name:"IAVA", value:"2015-A-0247-S");
  script_xref(name:"IAVA", value:"2020-A-0326");

  script_name(english:"SUSE SLES11 Security Update : libxml2 (SUSE-SU-2021:14729-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14729-1 advisory.

  - The xmlParserHandlePEReference function in parser.c in libxml2 before 2.9.2, as used in Web Listener in
    Oracle HTTP Server in Oracle Fusion Middleware 11.1.1.7.0, 12.1.2.0, and 12.1.3.0 and other products,
    loads external parameter entities regardless of whether entity substitution or validation is enabled,
    which allows remote attackers to cause a denial of service (resource consumption) via a crafted XML
    document. (CVE-2014-0191)

  - xmlParseBalancedChunkMemoryRecover in parser.c in libxml2 before 2.9.10 has a memory leak related to
    newDoc->oldNs. (CVE-2019-19956)

  - xmlSchemaPreRun in xmlschemas.c in libxml2 2.9.10 allows an xmlSchemaValidateStream memory leak.
    (CVE-2019-20388)

  - GNOME project libxml2 v2.9.10 has a global buffer over-read vulnerability in xmlEncodeEntitiesInternal at
    libxml2/entities.c. The issue has been fixed in commit 50f06b3e. (CVE-2020-24977)

  - xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file
    situation. (CVE-2020-7595)

  - There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted
    file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to
    confidentiality, integrity, and availability. (CVE-2021-3516)

  - There is a flaw in the xml entity encoding functionality of libxml2 in versions before 2.9.11. An attacker
    who is able to supply a crafted file to be processed by an application linked with the affected
    functionality of libxml2 could trigger an out-of-bounds read. The most likely impact of this flaw is to
    application availability, with some potential impact to confidentiality and integrity if an attacker is
    able to use memory information to further exploit the application. (CVE-2021-3517)

  - There's a flaw in libxml2 in versions before 2.9.11. An attacker who is able to submit a crafted file to
    be processed by an application linked with libxml2 could trigger a use-after-free. The greatest impact
    from this flaw is to confidentiality, integrity, and availability. (CVE-2021-3518)

  - A vulnerability found in libxml2 in versions before 2.9.11 shows that it did not propagate errors while
    parsing XML mixed content, causing a NULL dereference. If an untrusted XML document was parsed in recovery
    mode and post-validated, the flaw could be used to crash the application. The highest threat from this
    vulnerability is to system availability. (CVE-2021-3537)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185698");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-May/008797.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?054f377b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-0191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-20388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3537");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxml2, libxml2-32bit, libxml2-doc and / or libxml2-python packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'libxml2-2.7.6-0.77.36', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libxml2-32bit-2.7.6-0.77.36', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libxml2-32bit-2.7.6-0.77.36', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libxml2-doc-2.7.6-0.77.36', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libxml2-python-2.7.6-0.77.36', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libxml2-2.7.6-0.77.36', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libxml2-32bit-2.7.6-0.77.36', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libxml2-32bit-2.7.6-0.77.36', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libxml2-doc-2.7.6-0.77.36', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'libxml2-python-2.7.6-0.77.36', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxml2 / libxml2-32bit / libxml2-doc / libxml2-python');
}
