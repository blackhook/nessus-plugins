#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14399-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150522);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2017-9103",
    "CVE-2017-9104",
    "CVE-2017-9105",
    "CVE-2017-9106",
    "CVE-2017-9107",
    "CVE-2017-9108",
    "CVE-2017-9109"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14399-1");

  script_name(english:"SUSE SLES11 Security Update : adns (SUSE-SU-2020:14399-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14399-1 advisory.

  - An issue was discovered in adns before 1.5.2. pap_mailbox822 does not properly check st from
    adns__findlabel_next. Without this, an uninitialised stack value can be used as the first label length.
    Depending on the circumstances, an attacker might be able to trick adns into crashing the calling program,
    leaking aspects of the contents of some of its memory, causing it to allocate lots of memory, or perhaps
    overrunning a buffer. This is only possible with applications which make non-raw queries for SOA or RP
    records. (CVE-2017-9103)

  - An issue was discovered in adns before 1.5.2. It hangs, eating CPU, if a compression pointer loop is
    encountered. (CVE-2017-9104)

  - An issue was discovered in adns before 1.5.2. It corrupts a pointer when a nameserver speaks first because
    of a wrong number of pointer dereferences. This bug may well be exploitable as a remote code execution.
    (CVE-2017-9105)

  - An issue was discovered in adns before 1.5.2. adns_rr_info mishandles a bogus *datap. The general pattern
    for formatting integers is to sprintf into a fixed-size buffer. This is correct if the input is in the
    right range; if it isn't, the buffer may be overrun (depending on the sizes of the types on the current
    platform). Of course the inputs ought to be right. And there are pointers in there too, so perhaps one
    could say that the caller ought to check these things. It may be better to require the caller to make the
    pointer structure right, but to have the code here be defensive about (and tolerate with an error but
    without crashing) out-of-range integer values. So: it should defend each of these integer conversion sites
    with a check for the actual permitted range, and return adns_s_invaliddata if not. The lack of this check
    causes the SOA sign extension bug to be a serious security problem: the sign extended SOA value is out of
    range, and overruns the buffer when reconverted. This is related to sign extending SOA 32-bit integer
    fields, and use of a signed data type. (CVE-2017-9106)

  - An issue was discovered in adns before 1.5.2. It overruns reading a buffer if a domain ends with
    backslash. If the query domain ended with \, and adns_qf_quoteok_query was specified, qdparselabel would
    read additional bytes from the buffer and try to treat them as the escape sequence. It would depart the
    input buffer and start processing many bytes of arbitrary heap data as if it were the query domain.
    Eventually it would run out of input or find some other kind of error, and declare the query domain
    invalid. But before then it might outrun available memory and crash. In principle this could be a denial
    of service attack. (CVE-2017-9107)

  - An issue was discovered in adns before 1.5.2. adnshost mishandles a missing final newline on a stdin read.
    It is wrong to increment used as well as setting r, since used is incremented according to r, later.
    Rather one should be doing what read() would have done. Without this fix, adnshost may read and process
    one byte beyond the buffer, perhaps crashing or perhaps somehow leaking the value of that byte.
    (CVE-2017-9108)

  - An issue was discovered in adns before 1.5.2. It fails to ignore apparent answers before the first RR that
    was found the first time. when this is fixed, the second answer scan finds the same RRs at the first.
    Otherwise, adns can be confused by interleaving answers for the CNAME target, with the CNAME itself. In
    that case the answer data structure (on the heap) can be overrun. With this fixed, it prefers to look only
    at the answer RRs which come after the CNAME, which is at least arguably correct. (CVE-2017-9109)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172265");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-June/006979.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1e2b6e4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9109");
  script_set_attribute(attribute:"solution", value:
"Update the affected libadns1 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9109");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libadns1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'libadns1-1.4-75.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'libadns1-1.4-75.3', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libadns1');
}
