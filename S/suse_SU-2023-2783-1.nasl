#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2783-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(178008);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id(
    "CVE-2018-1000518",
    "CVE-2020-25659",
    "CVE-2020-36242",
    "CVE-2021-22569",
    "CVE-2021-22570",
    "CVE-2022-1941",
    "CVE-2022-3171"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2783-1");
  script_xref(name:"IAVA", value:"2022-A-0164");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : grpc, protobuf, python-Deprecated, python-PyGithub, python-aiocontextvars, python-avro, python-bcrypt, python-cryptography, python-cryptography-vectors, python-google-api-core, python-googleapis-common-protos, python-grpcio-gcp, python-humanfriendly, python-jsondiff, python-knack, python-opencensus, python-opencensus-context, python-opencensus-ext-threading, python-opentelemetry-api, python-psutil, python-pytest-asyncio, python-requests, python-websocket-client, python-websockets (SUSE-SU-2023:2783-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:2783-1 advisory.

  - aaugustin websockets version 4 contains a CWE-409: Improper Handling of Highly Compressed Data (Data
    Amplification) vulnerability in Servers and clients, unless configured with compression=None that can
    result in Denial of Service by memory exhaustion. This attack appear to be exploitable via Sending a
    specially crafted frame on an established connection. This vulnerability appears to have been fixed in 5.
    (CVE-2018-1000518)

  - python-cryptography 3.2 is vulnerable to Bleichenbacher timing attacks in the RSA decryption API, via
    timed processing of valid PKCS#1 v1.5 ciphertext. (CVE-2020-25659)

  - In the cryptography package before 3.3.2 for Python, certain sequences of update calls to symmetrically
    encrypt multi-GB values could result in an integer overflow and buffer overflow, as demonstrated by the
    Fernet class. (CVE-2020-36242)

  - An issue in protobuf-java allowed the interleaving of com.google.protobuf.UnknownFieldSet fields in such a
    way that would be processed out of order. A small malicious payload can occupy the parser for several
    minutes by creating large numbers of short-lived objects that cause frequent, repeated pauses. We
    recommend upgrading libraries beyond the vulnerable versions. (CVE-2021-22569)

  - Nullptr dereference when a null char is present in a proto symbol. The symbol is parsed incorrectly,
    leading to an unchecked call into the proto file's name during generation of the resulting error message.
    Since the symbol is incorrectly parsed, the file is nullptr. We recommend upgrading to version 3.15.0 or
    greater. (CVE-2021-22570)

  - A parsing vulnerability for the MessageSet type in the ProtocolBuffers versions prior to and including
    3.16.1, 3.17.3, 3.18.2, 3.19.4, 3.20.1 and 3.21.5 for protobuf-cpp, and versions prior to and including
    3.16.1, 3.17.3, 3.18.2, 3.19.4, 3.20.1 and 4.21.5 for protobuf-python can lead to out of memory failures.
    A specially crafted message with multiple key-value per elements creates parsing issues, and can lead to a
    Denial of Service against services receiving unsanitized input. We recommend upgrading to versions 3.18.3,
    3.19.5, 3.20.2, 3.21.6 for protobuf-cpp and 3.18.3, 3.19.5, 3.20.2, 4.21.6 for protobuf-python. Versions
    for 3.16 and 3.17 are no longer updated. (CVE-2022-1941)

  - A parsing issue with binary data in protobuf-java core and lite versions prior to 3.21.7, 3.20.3, 3.19.6
    and 3.16.3 can lead to a denial of service attack. Inputs containing multiple instances of non-repeated
    embedded messages with repeated or unknown fields causes objects to be converted back-n-forth between
    mutable and immutable forms, resulting in potentially long garbage collection pauses. We recommend
    updating to the versions mentioned above. (CVE-2022-3171)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1099269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1133277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1144068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1162343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204256");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-July/015451.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3b267c6a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1000518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36242");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3171");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36242");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:azure-cli-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grpc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgrpc++1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgrpc8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotobuf-lite20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotobuf-lite20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotobuf20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotobuf20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotoc20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotoc20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:protobuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:protobuf-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:protobuf-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-cryptography-vectors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-googleapis-common-protos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-grpcio-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-humanfriendly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-jsondiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-Automat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-Deprecated");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-PyGithub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-Twisted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-aiocontextvars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-avro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-constantly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cryptography-vectors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-google-api-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-googleapis-common-protos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-grpcio-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-humanfriendly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-hyperlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-incremental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-jsondiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-knack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-opencensus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-opencensus-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-opencensus-ext-threading");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-opentelemetry-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-psutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-pytest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-pytest-asyncio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-websocket-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-websockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-zope.interface");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(1|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP1/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1/2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'azure-cli-core-2.17.1-150100.6.18.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'grpc-devel-1.25.0-150100.3.3.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'grpc-devel-1.25.0-150100.3.3.3', 'sp':'1', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'grpc-source-1.25.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libgrpc++1-1.25.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libgrpc8-1.25.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libprotobuf-lite20-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-basesystem-release-15.1', 'sled-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libprotobuf-lite20-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libprotobuf-lite20-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-basesystem-release-15.1', 'sle-module-public-cloud-release-15.1', 'sled-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libprotobuf-lite20-32bit-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libprotobuf20-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libprotobuf20-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libprotobuf20-32bit-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libprotoc20-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'libprotoc20-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'libprotoc20-32bit-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'protobuf-devel-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'protobuf-devel-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'protobuf-java-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'protobuf-source-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python2-cryptography-vectors-3.3.2-150100.3.11.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-googleapis-common-protos-1.6.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-grpcio-1.25.0-150100.3.3.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-grpcio-gcp-0.2.2-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-jsondiff-1.3.0-150100.3.6.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-protobuf-3.9.2-150100.8.3.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python2-requests-2.25.1-150100.6.13.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-Automat-0.6.0-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-Deprecated-1.2.13-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-PyGithub-1.43.5-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-Twisted-17.9.0-150000.3.8.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-Twisted-17.9.0-150000.3.8.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-aiocontextvars-0.2.2-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-avro-1.11.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-cryptography-vectors-3.3.2-150100.3.11.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-google-api-core-1.14.2-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-googleapis-common-protos-1.6.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-grpcio-1.25.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-grpcio-gcp-0.2.2-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-humanfriendly-10.0-150100.6.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-incremental-17.5.0-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-jsondiff-1.3.0-150100.3.6.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-knack-0.9.0-150100.3.7.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-opencensus-0.8.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-opencensus-context-0.1.2-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-opencensus-ext-threading-0.1.2-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-opentelemetry-api-1.5.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-protobuf-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-pytest-3.10.1-150000.7.5.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-pytest-asyncio-0.8.0-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-requests-2.25.1-150100.6.13.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-websockets-9.1-150100.3.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1', 'SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'azure-cli-core-2.17.1-150100.6.18.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python2-requests-2.25.1-150100.6.13.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-Automat-0.6.0-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-Deprecated-1.2.13-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-PyGithub-1.43.5-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-aiocontextvars-0.2.2-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-avro-1.11.0-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-humanfriendly-10.0-150100.6.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-incremental-17.5.0-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-jsondiff-1.3.0-150100.3.6.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-knack-0.9.0-150100.3.7.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-opencensus-0.8.0-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-opencensus-context-0.1.2-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-opencensus-ext-threading-0.1.2-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-opentelemetry-api-1.5.0-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-pytest-3.10.1-150000.7.5.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-pytest-asyncio-0.8.0-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-requests-2.25.1-150100.6.13.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-websockets-9.1-150100.3.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'azure-cli-core-2.17.1-150100.6.18.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-Automat-0.6.0-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2']},
    {'reference':'python3-Deprecated-1.2.13-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-PyGithub-1.43.5-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-aiocontextvars-0.2.2-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-avro-1.11.0-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2']},
    {'reference':'python3-humanfriendly-10.0-150100.6.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2']},
    {'reference':'python3-incremental-17.5.0-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2']},
    {'reference':'python3-jsondiff-1.3.0-150100.3.6.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-knack-0.9.0-150100.3.7.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-opencensus-0.8.0-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-opencensus-context-0.1.2-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-opencensus-ext-threading-0.1.2-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-opentelemetry-api-1.5.0-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2']},
    {'reference':'python3-websockets-9.1-150100.3.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-ESPOS-release-3', 'SLE_RT-release-15.3', 'SUSE-Manager-Proxy-release-4.2']},
    {'reference':'azure-cli-core-2.17.1-150100.6.18.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-Deprecated-1.2.13-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-PyGithub-1.43.5-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-aiocontextvars-0.2.2-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-avro-1.11.0-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-server-applications-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-cryptography-vectors-3.3.2-150100.3.11.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-humanfriendly-10.0-150100.6.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-server-applications-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-jsondiff-1.3.0-150100.3.6.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-knack-0.9.0-150100.3.7.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-opencensus-0.8.0-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-opencensus-context-0.1.2-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-opencensus-ext-threading-0.1.2-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-opentelemetry-api-1.5.0-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-websockets-9.1-150100.3.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-server-applications-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'azure-cli-core-2.17.1-150100.6.18.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python2-humanfriendly-10.0-150100.6.3.3', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python2-humanfriendly-10.0-150100.6.3.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-packagehub-subpackages-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-humanfriendly-10.0-150100.6.3.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-jsondiff-1.3.0-150100.3.6.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-knack-0.9.0-150100.3.7.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5', 'SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'python2-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'python2-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'python2-requests-2.25.1-150100.6.13.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'python3-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'python3-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'python3-requests-2.25.1-150100.6.13.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python2-requests-2.25.1-150100.6.13.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'python3-Automat-0.6.0-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'python3-incremental-17.5.0-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python3-requests-2.25.1-150100.6.13.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'python3-Automat-0.6.0-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'python3-incremental-17.5.0-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.2']},
    {'reference':'azure-cli-core-2.17.1-150100.6.18.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-humanfriendly-10.0-150100.6.3.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-jsondiff-1.3.0-150100.3.6.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-knack-0.9.0-150100.3.7.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-websocket-client-1.3.2-150100.6.7.3', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libprotobuf-lite20-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libprotobuf20-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'libprotoc20-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'protobuf-devel-3.9.2-150100.8.3.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python2-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python3-Automat-0.6.0-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python3-Twisted-17.9.0-150000.3.8.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python3-constantly-15.1.0-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python3-cryptography-3.3.2-150100.7.15.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python3-hyperlink-17.2.1-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python3-incremental-17.5.0-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'python2-psutil-5.9.1-150100.6.6.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'python3-psutil-5.9.1-150100.6.6.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'python3-zope.interface-4.4.2-150000.3.4.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'azure-cli-core / grpc-devel / grpc-source / libgrpc++1 / libgrpc8 / etc');
}
