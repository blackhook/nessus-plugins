#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2016-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131434);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-20020", "CVE-2018-20021", "CVE-2018-20022", "CVE-2018-20024");

  script_name(english:"Debian DLA-2016-1 : ssvnc security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in the VNC code of ssvnc,
an encryption-capable VNC client..

The vulnerabilities referenced below are issues that have originally
been reported against Debian source package libvncserver (which also
ships the libvncclient shared library). The ssvnc source package in
Debian ships a custom-patched, stripped down and outdated variant of
libvncclient, thus some of libvncclient's security fixes required
porting over.

CVE-2018-20020

LibVNC contained heap out-of-bound write vulnerability inside
structure in VNC client code that can result remote code execution

CVE-2018-20021

LibVNC contained a CWE-835: Infinite loop vulnerability in VNC client
code. Vulnerability allows attacker to consume excessive amount of
resources like CPU and RAM

CVE-2018-20022

LibVNC contained multiple weaknesses CWE-665: Improper Initialization
vulnerability in VNC client code that allowed attackers to read stack
memory and could be abused for information disclosure. Combined with
another vulnerability, it could be used to leak stack memory layout
and in bypassing ASLR.

CVE-2018-20024

LibVNC contained NULL pointer dereference in VNC client code that
could result DoS.

For Debian 8 'Jessie', these problems have been fixed in version
1.0.29-2+deb8u1.

We recommend that you upgrade your ssvnc packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/ssvnc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ssvnc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20020");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssvnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
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
if (deb_check(release:"8.0", prefix:"ssvnc", reference:"1.0.29-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
