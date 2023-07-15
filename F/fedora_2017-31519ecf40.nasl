#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-31519ecf40.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104646);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2017-31519ecf40");

  script_name(english:"Fedora 26 : knot / knot-resolver (2017-31519ecf40)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Major updates for Knot DNS and Knot Resolver: Knot Resolver 1.5.0
(2017-11-02) ================================

Bugfixes

--------

  - fix loading modules on Darwin

Improvements

------------

  - new module ta_signal_query supporting Signaling Trust
    Anchor Knowledge using Keytag Query (RFC 8145 section
    5); it is enabled by default

  - attempt validation for more records but require it for
    fewer of them (e.g. avoids SERVFAIL when server adds
    extra records but omits RRSIGs)

Knot Resolver 1.4.0 (2017-09-22) ================================

Incompatible changes

--------------------

  - lua: query flag-sets are no longer represented as plain
    integers. kres.query.* no longer works, and kr_query_t
    lost trivial methods 'hasflag' and 'resolved'. You can
    instead write code like qry.flags.NO_0X20 = true.

Bugfixes

--------

  - fix exiting one of multiple forks (#150)

  - cache: change the way of using LMDB transactions. That
    in particular fixes some cases of using too much space
    with multiple kresd forks (#240).

Improvements

------------

  - policy.suffix: update the aho-corasick code (#200)

  - root hints are now loaded from a zonefile; exposed as
    hints.root_file(). You can override the path by defining
    ROOTHINTS during compilation.

  - policy.FORWARD: work around resolvers adding unsigned NS
    records (#248)

  - reduce unneeded records previously put into authority in
    wildcarded answers

Knot Resolver 1.3.3 (2017-08-09) ================================

Security

--------

  - Fix a critical DNSSEC flaw. Signatures might be accepted
    as valid even if the signed data was not in bailiwick of
    the DNSKEY used to sign it, assuming the trust chain to
    that DNSKEY was valid.

Bugfixes

--------

  - iterate: skip RRSIGs with bad label count instead of
    immediate SERVFAIL

  - utils: fix possible incorrect seeding of the random
    generator

  - modules/http: fix compatibility with the Prometheus text
    format

Improvements

------------

  - policy: implement remaining special-use domain names
    from RFC6761 (#205), and make these rules apply only if
    no other non-chain rule applies

Knot DNS 2.6.1 (2017-11-02) ===========================

Features :

---------

  - NSEC3 Opt-Out support in the DNSSEC signing

  - New CDS/CDNSKEY publish configuration option

Improvements :

-------------

  - Simplified DNSSEC log message with DNSKEY details

  - +tls-hostname in kdig implies +tls-ca if neither +tls-ca
    nor +tls-pin is given

  - New documentation sections for DNSSEC key rollovers and
    shared keys

  - Keymgr no longer prints useless algorithm number for
    generated key

  - Kdig prints unknown RCODE in a numeric format

  - Better support for LLVM libFuzzer

Bugfixes :

---------

  - Faulty DNAME semantic check if present in the zone apex
    and NSEC3 is used

  - Immediate zone flush not scheduled during the zone load
    event

  - Server crashes upon dynamic zone addition if a query
    module is loaded

  - Kdig fails to connect over TLS due to SNI is set to
    server IP address

  - Possible out-of-bounds memory access at the end of the
    input

  - TCP Fast Open enabled by default in kdig breaks TLS
    connection

Knot DNS 2.6.0 (2017-09-29) ===========================

Features :

---------

  - On-slave (inline) signing support

  - Automatic DNSSEC key algorithm rollover

  - Ed25519 algorithm support in DNSSEC (requires GnuTLS
    3.6.0)

  - New 'journal-content' and 'zonefile-load' configuration
    options

  - keymgr tries to run as user/group set in the
    configuration

  - Public-only DNSSEC key import into KASP DB via keymgr

  - NSEC3 resalt and parent DS query events are persistent
    in timer DB

  - New processing state for a response suppression within a
    query module

  - Enabled server side TCP Fast Open if supported

  - TCP Fast Open support in kdig

Improvements :

-------------

  - Better record owner compression if related to the
    previous rdata dname

  - NSEC(3) chain is no longer recomputed whole on every
    update

  - Remove inconsistent and unnecessary quoting in log files

  - Avoiding of overlapping key rollovers at a time

  - More DNSSSEC-related semantic checks

  - Extended timestamp format in keymgr

Bugfixes :

---------

  - Incorrect journal free space computation causing
    inefficient space handling

  - Interface-automatic broken on Linux in the presence of
    asymmetric routing

Knot DNS 2.5.6 (2017-11-02) ===========================

Improvements :

-------------

  - Keymgr no longer prints useless algorithm number for
    generated key

Bugfixes :

---------

  - Faulty DNAME semantic check if present in the zone apex
    and NSEC3 is used

  - Immediate zone flush not scheduled during the zone load
    event

  - Server crashes upon dynamic zone addition if a query
    module is loaded

  - Kdig fails to connect over TLS due to SNI is set to
    server IP address

Knot DNS 2.5.5 (2017-09-29) ===========================

Improvements :

-------------

  - Constant time memory comparison in the TSIG processing

  - Proper use of the ctype functions

  - Generated RRSIG records have inception time 90 minutes
    in the past

Bugfixes :

---------

  - Incorrect online signature for NSEC in the case of a
    CNAME record

  - Incorrect timestamps in dnstap records

  - EDNS Subnet Client validation rejects valid payloads

  - Module configuration semantic checks are not executed

  - Kzonecheck segfaults with unusual inputs

Knot DNS 2.5.4 (2017-08-31) ===========================

Improvements :

-------------

  - New minimum and maximum refresh interval config options
    (Thanks to Manabu Sonoda)

  - New warning when unforced flush with disabled zone file
    synchronization

  - New 'dnskey' keymgr command

  - Linking with libatomic on architectures that require it
    (Thanks to Pierre-Olivier Mercier)

  - Removed 'OK' from listing keymgr command outputs

  - Extended journal and keymgr documentation and logging

Bugfixes :

---------

  - Incorrect handling of specific corner-cases with
    zone-in-journal

  - The 'share' keymgr command doesn't work

  - Server crashes if configured with query-size and
    reply-size statistics options

  - Malformed big integer configuration values on some
    32-bit platforms

  - Keymgr uses local time when parsing date inputs

  - Memory leak in kdig upon IXFR query

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-31519ecf40"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected knot and / or knot-resolver packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:knot-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^26([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 26", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC26", reference:"knot-2.6.1-1.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"knot-resolver-1.5.0-1.fc26")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "knot / knot-resolver");
}
