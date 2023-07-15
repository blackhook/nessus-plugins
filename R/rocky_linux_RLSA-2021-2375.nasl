#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:2375.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157762);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2021-32027", "CVE-2021-32028", "CVE-2021-32029");
  script_xref(name:"RLSA", value:"2021:2375");
  script_xref(name:"IAVB", value:"2021-B-0036-S");

  script_name(english:"Rocky Linux 8 : postgresql:13 (RLSA-2021:2375)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:2375 advisory.

  - A flaw was found in postgresql in versions before 13.3, before 12.7, before 11.12, before 10.17 and before
    9.6.22. While modifying certain SQL array values, missing bounds checks let authenticated database users
    write arbitrary bytes to a wide area of server memory. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2021-32027)

  - A flaw was found in postgresql. Using an INSERT ... ON CONFLICT ... DO UPDATE command on a purpose-crafted
    table, an authenticated database user could read arbitrary bytes of server memory. The highest threat from
    this vulnerability is to data confidentiality. (CVE-2021-32028)

  - A flaw was found in postgresql. Using an UPDATE ... RETURNING command on a purpose-crafted table, an
    authenticated database user could read arbitrary bytes of server memory. The highest threat from this
    vulnerability is to data confidentiality. (CVE-2021-32029)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:2375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1956876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1956877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1956883");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32027");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-docs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plpython3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/RockyLinux/release');
if (isnull(release) || 'Rocky Linux' >!< release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'pgaudit-1.4.0-6.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-1.4'},
    {'reference':'pgaudit-1.4.0-6.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-1.4'},
    {'reference':'pgaudit-1.5.0-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-1.5'},
    {'reference':'pgaudit-1.5.0-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-1.5'},
    {'reference':'pgaudit-debuginfo-1.4.0-6.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-debuginfo-1.4'},
    {'reference':'pgaudit-debuginfo-1.4.0-6.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-debuginfo-1.4'},
    {'reference':'pgaudit-debuginfo-1.5.0-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-debuginfo-1.5'},
    {'reference':'pgaudit-debuginfo-1.5.0-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-debuginfo-1.5'},
    {'reference':'pgaudit-debugsource-1.4.0-6.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-debugsource-1.4'},
    {'reference':'pgaudit-debugsource-1.4.0-6.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-debugsource-1.4'},
    {'reference':'pgaudit-debugsource-1.5.0-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-debugsource-1.5'},
    {'reference':'pgaudit-debugsource-1.5.0-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'pgaudit-debugsource-1.5'},
    {'reference':'postgres-decoderbufs-0.10.0-2.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-0.10.0-2.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-debuginfo-0.10.0-2.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-debuginfo-0.10.0-2.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-debugsource-0.10.0-2.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgres-decoderbufs-debugsource-0.10.0-2.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'postgresql-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-10'},
    {'reference':'postgresql-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-10'},
    {'reference':'postgresql-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-12'},
    {'reference':'postgresql-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-12'},
    {'reference':'postgresql-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-13'},
    {'reference':'postgresql-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-13'},
    {'reference':'postgresql-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-9'},
    {'reference':'postgresql-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-9'},
    {'reference':'postgresql-contrib-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-10'},
    {'reference':'postgresql-contrib-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-10'},
    {'reference':'postgresql-contrib-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-12'},
    {'reference':'postgresql-contrib-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-12'},
    {'reference':'postgresql-contrib-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-13'},
    {'reference':'postgresql-contrib-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-13'},
    {'reference':'postgresql-contrib-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-9'},
    {'reference':'postgresql-contrib-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-9'},
    {'reference':'postgresql-contrib-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-debuginfo-10'},
    {'reference':'postgresql-contrib-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-debuginfo-10'},
    {'reference':'postgresql-contrib-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-debuginfo-12'},
    {'reference':'postgresql-contrib-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-debuginfo-12'},
    {'reference':'postgresql-contrib-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-debuginfo-13'},
    {'reference':'postgresql-contrib-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-debuginfo-13'},
    {'reference':'postgresql-contrib-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-debuginfo-9'},
    {'reference':'postgresql-contrib-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-contrib-debuginfo-9'},
    {'reference':'postgresql-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debuginfo-10'},
    {'reference':'postgresql-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debuginfo-10'},
    {'reference':'postgresql-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debuginfo-12'},
    {'reference':'postgresql-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debuginfo-12'},
    {'reference':'postgresql-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debuginfo-13'},
    {'reference':'postgresql-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debuginfo-13'},
    {'reference':'postgresql-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debuginfo-9'},
    {'reference':'postgresql-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debuginfo-9'},
    {'reference':'postgresql-debugsource-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debugsource-10'},
    {'reference':'postgresql-debugsource-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debugsource-10'},
    {'reference':'postgresql-debugsource-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debugsource-12'},
    {'reference':'postgresql-debugsource-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debugsource-12'},
    {'reference':'postgresql-debugsource-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debugsource-13'},
    {'reference':'postgresql-debugsource-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debugsource-13'},
    {'reference':'postgresql-debugsource-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debugsource-9'},
    {'reference':'postgresql-debugsource-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-debugsource-9'},
    {'reference':'postgresql-docs-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-10'},
    {'reference':'postgresql-docs-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-10'},
    {'reference':'postgresql-docs-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-12'},
    {'reference':'postgresql-docs-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-12'},
    {'reference':'postgresql-docs-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-13'},
    {'reference':'postgresql-docs-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-13'},
    {'reference':'postgresql-docs-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-9'},
    {'reference':'postgresql-docs-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-9'},
    {'reference':'postgresql-docs-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-debuginfo-10'},
    {'reference':'postgresql-docs-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-debuginfo-10'},
    {'reference':'postgresql-docs-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-debuginfo-12'},
    {'reference':'postgresql-docs-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-debuginfo-12'},
    {'reference':'postgresql-docs-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-debuginfo-13'},
    {'reference':'postgresql-docs-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-debuginfo-13'},
    {'reference':'postgresql-docs-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-debuginfo-9'},
    {'reference':'postgresql-docs-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-docs-debuginfo-9'},
    {'reference':'postgresql-plperl-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-10'},
    {'reference':'postgresql-plperl-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-10'},
    {'reference':'postgresql-plperl-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-12'},
    {'reference':'postgresql-plperl-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-12'},
    {'reference':'postgresql-plperl-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-13'},
    {'reference':'postgresql-plperl-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-13'},
    {'reference':'postgresql-plperl-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-9'},
    {'reference':'postgresql-plperl-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-9'},
    {'reference':'postgresql-plperl-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-debuginfo-10'},
    {'reference':'postgresql-plperl-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-debuginfo-10'},
    {'reference':'postgresql-plperl-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-debuginfo-12'},
    {'reference':'postgresql-plperl-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-debuginfo-12'},
    {'reference':'postgresql-plperl-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-debuginfo-13'},
    {'reference':'postgresql-plperl-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-debuginfo-13'},
    {'reference':'postgresql-plperl-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-debuginfo-9'},
    {'reference':'postgresql-plperl-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plperl-debuginfo-9'},
    {'reference':'postgresql-plpython3-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-10'},
    {'reference':'postgresql-plpython3-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-10'},
    {'reference':'postgresql-plpython3-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-12'},
    {'reference':'postgresql-plpython3-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-12'},
    {'reference':'postgresql-plpython3-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-13'},
    {'reference':'postgresql-plpython3-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-13'},
    {'reference':'postgresql-plpython3-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-9'},
    {'reference':'postgresql-plpython3-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-9'},
    {'reference':'postgresql-plpython3-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-debuginfo-10'},
    {'reference':'postgresql-plpython3-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-debuginfo-10'},
    {'reference':'postgresql-plpython3-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-debuginfo-12'},
    {'reference':'postgresql-plpython3-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-debuginfo-12'},
    {'reference':'postgresql-plpython3-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-debuginfo-13'},
    {'reference':'postgresql-plpython3-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-debuginfo-13'},
    {'reference':'postgresql-plpython3-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-debuginfo-9'},
    {'reference':'postgresql-plpython3-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-plpython3-debuginfo-9'},
    {'reference':'postgresql-pltcl-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-10'},
    {'reference':'postgresql-pltcl-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-10'},
    {'reference':'postgresql-pltcl-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-12'},
    {'reference':'postgresql-pltcl-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-12'},
    {'reference':'postgresql-pltcl-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-13'},
    {'reference':'postgresql-pltcl-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-13'},
    {'reference':'postgresql-pltcl-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-9'},
    {'reference':'postgresql-pltcl-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-9'},
    {'reference':'postgresql-pltcl-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-debuginfo-10'},
    {'reference':'postgresql-pltcl-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-debuginfo-10'},
    {'reference':'postgresql-pltcl-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-debuginfo-12'},
    {'reference':'postgresql-pltcl-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-debuginfo-12'},
    {'reference':'postgresql-pltcl-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-debuginfo-13'},
    {'reference':'postgresql-pltcl-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-debuginfo-13'},
    {'reference':'postgresql-pltcl-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-debuginfo-9'},
    {'reference':'postgresql-pltcl-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-pltcl-debuginfo-9'},
    {'reference':'postgresql-server-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-10'},
    {'reference':'postgresql-server-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-10'},
    {'reference':'postgresql-server-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-12'},
    {'reference':'postgresql-server-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-12'},
    {'reference':'postgresql-server-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-13'},
    {'reference':'postgresql-server-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-13'},
    {'reference':'postgresql-server-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-9'},
    {'reference':'postgresql-server-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-9'},
    {'reference':'postgresql-server-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-debuginfo-10'},
    {'reference':'postgresql-server-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-debuginfo-10'},
    {'reference':'postgresql-server-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-debuginfo-12'},
    {'reference':'postgresql-server-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-debuginfo-12'},
    {'reference':'postgresql-server-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-debuginfo-13'},
    {'reference':'postgresql-server-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-debuginfo-13'},
    {'reference':'postgresql-server-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-debuginfo-9'},
    {'reference':'postgresql-server-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-debuginfo-9'},
    {'reference':'postgresql-server-devel-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-10'},
    {'reference':'postgresql-server-devel-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-10'},
    {'reference':'postgresql-server-devel-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-12'},
    {'reference':'postgresql-server-devel-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-12'},
    {'reference':'postgresql-server-devel-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-13'},
    {'reference':'postgresql-server-devel-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-13'},
    {'reference':'postgresql-server-devel-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-9'},
    {'reference':'postgresql-server-devel-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-9'},
    {'reference':'postgresql-server-devel-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-debuginfo-10'},
    {'reference':'postgresql-server-devel-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-debuginfo-10'},
    {'reference':'postgresql-server-devel-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-debuginfo-12'},
    {'reference':'postgresql-server-devel-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-debuginfo-12'},
    {'reference':'postgresql-server-devel-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-debuginfo-13'},
    {'reference':'postgresql-server-devel-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-debuginfo-13'},
    {'reference':'postgresql-server-devel-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-debuginfo-9'},
    {'reference':'postgresql-server-devel-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-server-devel-debuginfo-9'},
    {'reference':'postgresql-static-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-static-10'},
    {'reference':'postgresql-static-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-static-10'},
    {'reference':'postgresql-static-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-static-12'},
    {'reference':'postgresql-static-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-static-12'},
    {'reference':'postgresql-static-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-static-13'},
    {'reference':'postgresql-static-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-static-13'},
    {'reference':'postgresql-static-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-static-9'},
    {'reference':'postgresql-static-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-static-9'},
    {'reference':'postgresql-test-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-10'},
    {'reference':'postgresql-test-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-10'},
    {'reference':'postgresql-test-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-12'},
    {'reference':'postgresql-test-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-12'},
    {'reference':'postgresql-test-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-13'},
    {'reference':'postgresql-test-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-13'},
    {'reference':'postgresql-test-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-9'},
    {'reference':'postgresql-test-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-9'},
    {'reference':'postgresql-test-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-debuginfo-10'},
    {'reference':'postgresql-test-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-debuginfo-10'},
    {'reference':'postgresql-test-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-debuginfo-12'},
    {'reference':'postgresql-test-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-debuginfo-12'},
    {'reference':'postgresql-test-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-debuginfo-13'},
    {'reference':'postgresql-test-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-debuginfo-13'},
    {'reference':'postgresql-test-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-debuginfo-9'},
    {'reference':'postgresql-test-debuginfo-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-debuginfo-9'},
    {'reference':'postgresql-test-rpm-macros-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-rpm-macros-10'},
    {'reference':'postgresql-test-rpm-macros-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-rpm-macros-10'},
    {'reference':'postgresql-test-rpm-macros-12.7-1.module+el8.4.0+587+d46efd10', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-rpm-macros-12'},
    {'reference':'postgresql-test-rpm-macros-13.3-1.module+el8.4.0+546+3620623e', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-rpm-macros-13'},
    {'reference':'postgresql-test-rpm-macros-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-rpm-macros-9'},
    {'reference':'postgresql-test-rpm-macros-9.6.22-1.module+el8.4.0+547+51cac6db', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-test-rpm-macros-9'},
    {'reference':'postgresql-upgrade-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-10'},
    {'reference':'postgresql-upgrade-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-10'},
    {'reference':'postgresql-upgrade-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-12'},
    {'reference':'postgresql-upgrade-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-12'},
    {'reference':'postgresql-upgrade-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-13'},
    {'reference':'postgresql-upgrade-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-13'},
    {'reference':'postgresql-upgrade-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-debuginfo-10'},
    {'reference':'postgresql-upgrade-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-debuginfo-10'},
    {'reference':'postgresql-upgrade-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-debuginfo-12'},
    {'reference':'postgresql-upgrade-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-debuginfo-12'},
    {'reference':'postgresql-upgrade-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-debuginfo-13'},
    {'reference':'postgresql-upgrade-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-debuginfo-13'},
    {'reference':'postgresql-upgrade-devel-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-10'},
    {'reference':'postgresql-upgrade-devel-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-10'},
    {'reference':'postgresql-upgrade-devel-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-12'},
    {'reference':'postgresql-upgrade-devel-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-12'},
    {'reference':'postgresql-upgrade-devel-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-13'},
    {'reference':'postgresql-upgrade-devel-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-13'},
    {'reference':'postgresql-upgrade-devel-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-debuginfo-10'},
    {'reference':'postgresql-upgrade-devel-debuginfo-10.17-1.module+el8.4.0+548+9eccbe3f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-debuginfo-10'},
    {'reference':'postgresql-upgrade-devel-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-debuginfo-12'},
    {'reference':'postgresql-upgrade-devel-debuginfo-12.7-1.module+el8.4.0+587+d46efd10', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-debuginfo-12'},
    {'reference':'postgresql-upgrade-devel-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-debuginfo-13'},
    {'reference':'postgresql-upgrade-devel-debuginfo-13.3-1.module+el8.4.0+546+3620623e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'postgresql-upgrade-devel-debuginfo-13'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pgaudit / pgaudit-debuginfo / pgaudit-debugsource / etc');
}
