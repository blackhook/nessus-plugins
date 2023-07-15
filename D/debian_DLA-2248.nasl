#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2248-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137418);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");

  script_name(english:"Debian DLA-2248-1 : intel-microcode security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The following CVE(s) were reported against src:intel-microcode.

CVE-2020-0543

A new domain bypass transient execution attack known as Special
Register Buffer Data Sampling (SRBDS) has been found. This flaw allows
data values from special internal registers to be leaked by an
attacker able to execute code on any core of the CPU. An unprivileged,
local attacker can use this flaw to infer values returned by affected
instructions known to be commonly used during cryptographic operations
that rely on uniqueness, secrecy, or both.

CVE-2020-0548

A flaw was found in Intel processors where a local attacker is able to
gain information about registers used for vector calculations by
observing register states from other processes running on the system.
This results in a race condition where store buffers, which were not
cleared, could be read by another process or a CPU sibling. The
highest threat from this vulnerability is data confidentiality where
an attacker could read arbitrary data as it passes through the
processor.

CVE-2020-0549

A microarchitectural timing flaw was found on some Intel processors. A
corner case exists where data in-flight during the eviction process
can end up in the 'fill buffers' and not properly cleared
by the MDS mitigations. The fill buffer contents (which were expected
to be blank) can be inferred using MDS or TAA style attack methods to
allow a local attacker to infer fill buffer values.

For Debian 8 'Jessie', these problems have been fixed in version
3.20200609.2~deb8u1.

We recommend that you upgrade your intel-microcode packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/intel-microcode"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected intel-microcode package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:intel-microcode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"intel-microcode", reference:"3.20200609.2~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
