#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2014-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131432);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-6053", "CVE-2018-7225", "CVE-2019-15681");
  script_bugtraq_id(70092);
  script_xref(name:"IAVA", value:"2020-A-0381");

  script_name(english:"Debian DLA-2014-1 : vino security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in the VNC code of vino,
a desktop sharing utility for the GNOME desktop environment.

The vulnerabilities referenced below are issues that have originally
been reported against Debian source package libvncserver. The vino
source package in Debian ships a custom-patched and stripped down
variant of libvncserver, thus some of libvncserver's security fixes
required porting over.

CVE-2014-6053

The rfbProcessClientNormalMessage function in libvncserver/rfbserver.c
in LibVNCServer did not properly handle attempts to send a large
amount of ClientCutText data, which allowed remote attackers to cause
a denial of service (memory consumption or daemon crash) via a crafted
message that was processed by using a single unchecked malloc.

CVE-2018-7225

An issue was discovered in LibVNCServer.
rfbProcessClientNormalMessage() in rfbserver.c did not sanitize
msg.cct.length, leading to access to uninitialized and potentially
sensitive data or possibly unspecified other impact (e.g., an integer
overflow) via specially crafted VNC packets.

CVE-2019-15681

LibVNC contained a memory leak (CWE-655) in VNC server code, which
allowed an attacker to read stack memory and could be abused for
information disclosure. Combined with another vulnerability, it could
be used to leak stack memory and bypass ASLR. This attack appeared to
be exploitable via network connectivity.

For Debian 8 'Jessie', these problems have been fixed in version
3.14.0-2+deb8u1.

We recommend that you upgrade your vino packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00032.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/vino");
  script_set_attribute(attribute:"solution", value:"Upgrade the affected vino package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vino");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"vino", reference:"3.14.0-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
