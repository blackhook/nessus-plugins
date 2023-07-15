#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-9013b5e75d.
#

include("compat.inc");

if (description)
{
  script_id(128134);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/02");

  script_cve_id("CVE-2019-1010057", "CVE-2019-14459");
  script_xref(name:"FEDORA", value:"2019-9013b5e75d");

  script_name(english:"Fedora 29 : nfdump (2019-9013b5e75d)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"2019-08-14

  - Fix compile issues

  - Fix output buffer size for lzo1x_decompress_safe()

2019-08-07

  - Fix VerifyExtensionMap #179

2019-08-06

  - Fix compile errors

2019-08-05

  - Fix nfdump.1 man page. #175

  - Fix off by 1 array. #173

  - Fix use after free in ModifyCompressFile

  - Add bound checks in AddExporterStat #174

  - Add bound checks in AddSamplerInfo #176

  - Add bound checks in AddExporterInfo

  - Fix checks in InsertExtensionMap #177

  - Remove COMPAT15 code - should no longer be needed.

  - Move version to v1.6.18

  - Merge pull request #167

  - Cleanup old code

  - Replace depricated pcap_lookupdev call in nfpcapd

2019-07-31

  - Add early record size sanity check also for nfprofile,
    nfanon and nfreplay

2019-07-26

  - nfpcapd cleanup, add some more monitoring

  - Fix hbo_exporter.c:249_1 segfault 

  - Fix hbo_nffile_inline.c:85_1 segfault

  - Fix hbo_nfx.c:216_3 segfault

  - Update minilzo to v2.10

  - Change to safe lzo decompress function

2019-07-25

  - Rework nfpcapd and add it officially to the nfdump
    collection.

  - Add nfpcapd man page

  - Fix potential unsigned integer underflow #171

2019-07-16

  - Add latency extension if dumping flowcache

2019-07-15

  - Fix typos

  - Fix exporter struct inconsistancies. Coredump on ARM
    otherwise.

2019-07-02

  - Add ipfix element #150, #151 unix time start/end

  - Fix display bug raw record

2019-06-01

  - Add ipfix dyn element handling.

  - Add empty m4 directory - keep autoconf happy

2019-06-01

  - Fix issue #162 - ipfix mpls sequece.

  - Fix issue #156 - print flowtable index error

2019-03-17

  - Fix spec file

  - Remove non thread safe logging in nfpcapd

2018-11-24

  - Fix protocol tag for protocol 87 - TCF - #130

  - Add TCP flags ECN,CVR - #132

  - Fix some error messages to be printed to the correct
    stream #135

  - Add missing -M command line help to nfcapd

  - Remove padding byte warning in log #141

  - Fix bug to accept -y compression flag in nfcapd. - #145

2018-06-24

  - Fix bookkeeper type - use key_t

  - Add multiple packet repeaters to nfcapd/sfcapd. Up to 8
    repeaters (-R) can be defined.

  - Ignore OSX .DS_Store files in -R file list

  - Add CISCO ASA elements initiatorPackets (298)
    responderPackets (299)

  - Merge #120 pull request for -z parameter to nfreplay

  - Update man page nfreplay

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-9013b5e75d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nfdump package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nfdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"nfdump-1.6.18-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nfdump");
}
