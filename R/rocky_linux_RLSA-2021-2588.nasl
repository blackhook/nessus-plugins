#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:2588.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157798);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2019-3881",
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-10663",
    "CVE-2020-10933",
    "CVE-2020-25613",
    "CVE-2021-28965"
  );
  script_xref(name:"RLSA", value:"2021:2588");

  script_name(english:"Rocky Linux 8 : ruby:2.6 (RLSA-2021:2588)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:2588 advisory.

  - Bundler prior to 2.1.0 uses a predictable path in /tmp/, created with insecure permissions as a storage
    location for gems, if locations under the user's home directory are not available. If Bundler is used in a
    scenario where the user does not have a writable home directory, an attacker could place malicious code in
    this directory that would be later loaded and executed. (CVE-2019-3881)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 mishandles path checking within
    File.fnmatch functions. (CVE-2019-15845)

  - WEBrick::HTTPAuth::DigestAuth in Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 has a
    regular expression Denial of Service cause by looping/backtracking. A victim must expose a WEBrick server
    that uses DigestAuth to the Internet or a untrusted network. (CVE-2019-16201)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows HTTP Response Splitting. If a
    program using WEBrick inserts untrusted input into the response header, an attacker can exploit it to
    insert a newline character to split a header, and inject malicious content to deceive clients. NOTE: this
    issue exists because of an incomplete fix for CVE-2017-17742, which addressed the CRLF vector, but did not
    address an isolated CR or an isolated LF. (CVE-2019-16254)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows code injection if the first
    argument (aka the command argument) to Shell#[] or Shell#test in lib/shell.rb is untrusted data. An
    attacker can exploit this to call an arbitrary Ruby method. (CVE-2019-16255)

  - The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through 2.4.9, 2.5 through 2.5.7, and 2.6 through
    2.6.5, has an Unsafe Object Creation Vulnerability. This is quite similar to CVE-2013-0269, but does not
    rely on poor garbage-collection behavior within Ruby. Specifically, use of JSON parsing methods can lead
    to creation of a malicious object within the interpreter, with adverse effects that are application-
    dependent. (CVE-2020-10663)

  - An issue was discovered in Ruby 2.5.x through 2.5.7, 2.6.x through 2.6.5, and 2.7.0. If a victim calls
    BasicSocket#read_nonblock(requested_size, buffer, exception: false), the method resizes the buffer to fit
    the requested size, but no data is copied. Thus, the buffer string provides the previous value of the
    heap. This may expose possibly sensitive data from the interpreter. (CVE-2020-10933)

  - An issue was discovered in Ruby through 2.5.8, 2.6.x through 2.6.6, and 2.7.x through 2.7.1. WEBrick, a
    simple HTTP server bundled with Ruby, had not checked the transfer-encoding header value rigorously. An
    attacker may potentially exploit this issue to bypass a reverse proxy (which also has a poor header
    check), which may lead to an HTTP Request Smuggling attack. (CVE-2020-25613)

  - The REXML gem before 3.2.5 in Ruby before 2.6.7, 2.7.x before 2.7.3, and 3.x before 3.0.1 does not
    properly address XML round-trip issues. An incorrect document can be produced after parsing and
    serializing. (CVE-2021-28965)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:2588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1651826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1773728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1789407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1789556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1793683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1827500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1833291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1883623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1947526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1952627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1954968");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pcs-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-abrt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bson-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bson-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-bundler-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-mysql2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:rubygem-pg-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
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
    {'reference':'pcs-0.10.8-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-0.10.8-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-snmp-0.10.8-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pcs-snmp-0.10.8-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-abrt-0.3.0-4.module+el8.4.0+592+03ff458a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-abrt-0.3'},
    {'reference':'rubygem-abrt-0.4.0-1.module+el8.4.0+594+11b6673a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-abrt-0.4'},
    {'reference':'rubygem-abrt-doc-0.3.0-4.module+el8.4.0+592+03ff458a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-abrt-doc-0.3'},
    {'reference':'rubygem-abrt-doc-0.4.0-1.module+el8.4.0+594+11b6673a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-abrt-doc-0.4'},
    {'reference':'rubygem-bson-4.3.0-2.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-4.3'},
    {'reference':'rubygem-bson-4.3.0-2.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-4.3'},
    {'reference':'rubygem-bson-4.5.0-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-4.5'},
    {'reference':'rubygem-bson-4.5.0-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-4.5'},
    {'reference':'rubygem-bson-4.8.1-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-4.8'},
    {'reference':'rubygem-bson-4.8.1-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-4.8'},
    {'reference':'rubygem-bson-debuginfo-4.3.0-2.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debuginfo-4.3'},
    {'reference':'rubygem-bson-debuginfo-4.3.0-2.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debuginfo-4.3'},
    {'reference':'rubygem-bson-debuginfo-4.5.0-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debuginfo-4.5'},
    {'reference':'rubygem-bson-debuginfo-4.5.0-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debuginfo-4.5'},
    {'reference':'rubygem-bson-debuginfo-4.8.1-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debuginfo-4.8'},
    {'reference':'rubygem-bson-debuginfo-4.8.1-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debuginfo-4.8'},
    {'reference':'rubygem-bson-debugsource-4.3.0-2.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debugsource-4.3'},
    {'reference':'rubygem-bson-debugsource-4.3.0-2.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debugsource-4.3'},
    {'reference':'rubygem-bson-debugsource-4.5.0-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debugsource-4.5'},
    {'reference':'rubygem-bson-debugsource-4.5.0-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debugsource-4.5'},
    {'reference':'rubygem-bson-debugsource-4.8.1-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debugsource-4.8'},
    {'reference':'rubygem-bson-debugsource-4.8.1-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-debugsource-4.8'},
    {'reference':'rubygem-bson-doc-4.3.0-2.module+el8.4.0+592+03ff458a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-doc-4.3'},
    {'reference':'rubygem-bson-doc-4.5.0-1.module+el8.4.0+593+8d7f9f0c', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-doc-4.5'},
    {'reference':'rubygem-bson-doc-4.8.1-1.module+el8.4.0+594+11b6673a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-bson-doc-4.8'},
    {'reference':'rubygem-bundler-1.16.1-3.module+el8.4.0+592+03ff458a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-bundler-doc-1.16.1-3.module+el8.4.0+592+03ff458a', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rubygem-mongo-2.11.3-1.module+el8.4.0+594+11b6673a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mongo-2.11'},
    {'reference':'rubygem-mongo-2.5.1-2.module+el8.4.0+592+03ff458a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mongo-2.5'},
    {'reference':'rubygem-mongo-2.8.0-1.module+el8.4.0+593+8d7f9f0c', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mongo-2.8'},
    {'reference':'rubygem-mongo-doc-2.11.3-1.module+el8.4.0+594+11b6673a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mongo-doc-2.11'},
    {'reference':'rubygem-mongo-doc-2.5.1-2.module+el8.4.0+592+03ff458a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mongo-doc-2.5'},
    {'reference':'rubygem-mongo-doc-2.8.0-1.module+el8.4.0+593+8d7f9f0c', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mongo-doc-2.8'},
    {'reference':'rubygem-mysql2-0.4.10-4.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-0.4'},
    {'reference':'rubygem-mysql2-0.4.10-4.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-0.4'},
    {'reference':'rubygem-mysql2-0.5.2-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-0.5'},
    {'reference':'rubygem-mysql2-0.5.2-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-0.5'},
    {'reference':'rubygem-mysql2-0.5.3-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-0.5'},
    {'reference':'rubygem-mysql2-0.5.3-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-0.5'},
    {'reference':'rubygem-mysql2-debuginfo-0.4.10-4.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debuginfo-0.4'},
    {'reference':'rubygem-mysql2-debuginfo-0.4.10-4.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debuginfo-0.4'},
    {'reference':'rubygem-mysql2-debuginfo-0.5.2-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debuginfo-0.5'},
    {'reference':'rubygem-mysql2-debuginfo-0.5.2-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debuginfo-0.5'},
    {'reference':'rubygem-mysql2-debuginfo-0.5.3-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debuginfo-0.5'},
    {'reference':'rubygem-mysql2-debuginfo-0.5.3-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debuginfo-0.5'},
    {'reference':'rubygem-mysql2-debugsource-0.4.10-4.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debugsource-0.4'},
    {'reference':'rubygem-mysql2-debugsource-0.4.10-4.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debugsource-0.4'},
    {'reference':'rubygem-mysql2-debugsource-0.5.2-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debugsource-0.5'},
    {'reference':'rubygem-mysql2-debugsource-0.5.2-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debugsource-0.5'},
    {'reference':'rubygem-mysql2-debugsource-0.5.3-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debugsource-0.5'},
    {'reference':'rubygem-mysql2-debugsource-0.5.3-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-debugsource-0.5'},
    {'reference':'rubygem-mysql2-doc-0.4.10-4.module+el8.4.0+592+03ff458a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-doc-0.4'},
    {'reference':'rubygem-mysql2-doc-0.5.2-1.module+el8.4.0+593+8d7f9f0c', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-doc-0.5'},
    {'reference':'rubygem-mysql2-doc-0.5.3-1.module+el8.4.0+594+11b6673a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-mysql2-doc-0.5'},
    {'reference':'rubygem-pg-1.0.0-2.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-1.0'},
    {'reference':'rubygem-pg-1.0.0-2.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-1.0'},
    {'reference':'rubygem-pg-1.1.4-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-1.1'},
    {'reference':'rubygem-pg-1.1.4-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-1.1'},
    {'reference':'rubygem-pg-1.2.3-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-1.2'},
    {'reference':'rubygem-pg-1.2.3-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-1.2'},
    {'reference':'rubygem-pg-debuginfo-1.0.0-2.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debuginfo-1.0'},
    {'reference':'rubygem-pg-debuginfo-1.0.0-2.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debuginfo-1.0'},
    {'reference':'rubygem-pg-debuginfo-1.1.4-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debuginfo-1.1'},
    {'reference':'rubygem-pg-debuginfo-1.1.4-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debuginfo-1.1'},
    {'reference':'rubygem-pg-debuginfo-1.2.3-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debuginfo-1.2'},
    {'reference':'rubygem-pg-debuginfo-1.2.3-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debuginfo-1.2'},
    {'reference':'rubygem-pg-debugsource-1.0.0-2.module+el8.4.0+592+03ff458a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debugsource-1.0'},
    {'reference':'rubygem-pg-debugsource-1.0.0-2.module+el8.4.0+592+03ff458a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debugsource-1.0'},
    {'reference':'rubygem-pg-debugsource-1.1.4-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debugsource-1.1'},
    {'reference':'rubygem-pg-debugsource-1.1.4-1.module+el8.4.0+593+8d7f9f0c', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debugsource-1.1'},
    {'reference':'rubygem-pg-debugsource-1.2.3-1.module+el8.4.0+594+11b6673a', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debugsource-1.2'},
    {'reference':'rubygem-pg-debugsource-1.2.3-1.module+el8.4.0+594+11b6673a', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-debugsource-1.2'},
    {'reference':'rubygem-pg-doc-1.0.0-2.module+el8.4.0+592+03ff458a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-doc-1.0'},
    {'reference':'rubygem-pg-doc-1.1.4-1.module+el8.4.0+593+8d7f9f0c', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-doc-1.1'},
    {'reference':'rubygem-pg-doc-1.2.3-1.module+el8.4.0+594+11b6673a', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'rubygem-pg-doc-1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pcs / pcs-snmp / rubygem-abrt / rubygem-abrt-doc / rubygem-bson / etc');
}
