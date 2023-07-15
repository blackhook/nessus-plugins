#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-809-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(96884);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925", "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929", "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933", "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937", "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973", "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984", "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993", "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203", "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342", "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485", "CVE-2017-5486");

  script_name(english:"Debian DLA-809-1 : tcpdump security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in tcpdump, a
command-line network traffic analyzer. These vulnerabilities might
result in denial of service or the execution of arbitrary code.

CVE-2016-7922

Buffer overflow in parser.

CVE-2016-7923

Buffer overflow in parser.

CVE-2016-7924

Buffer overflow in parser.

CVE-2016-7925

Buffer overflow in parser.

CVE-2016-7926

Buffer overflow in parser.

CVE-2016-7927

Buffer overflow in parser.

CVE-2016-7928

Buffer overflow in parser.

CVE-2016-7929

Buffer overflow in parser.

CVE-2016-7930

Buffer overflow in parser.

CVE-2016-7931

Buffer overflow in parser.

CVE-2016-7932

Buffer overflow in parser.

CVE-2016-7933

Buffer overflow in parser.

CVE-2016-7934

Buffer overflow in parser.

CVE-2016-7935

Buffer overflow in parser.

CVE-2016-7936

Buffer overflow in parser.

CVE-2016-7937

Buffer overflow in parser.

CVE-2016-7938

Buffer overflow in parser.

CVE-2016-7939

Buffer overflow in parser.

CVE-2016-7940

Buffer overflow in parser.

CVE-2016-7973

Buffer overflow in parser.

CVE-2016-7974

Buffer overflow in parser.

CVE-2016-7975

Buffer overflow in parser.

CVE-2016-7983

Buffer overflow in parser.

CVE-2016-7984

Buffer overflow in parser.

CVE-2016-7985

Buffer overflow in parser.

CVE-2016-7986

Buffer overflow in parser.

CVE-2016-7992

Buffer overflow in parser.

CVE-2016-7993

Buffer overflow in parser.

CVE-2016-8574

Buffer overflow in parser.

CVE-2016-8575

Buffer overflow in parser.

CVE-2017-5202

Buffer overflow in parser.

CVE-2017-5203

Buffer overflow in parser.

CVE-2017-5204

Buffer overflow in parser.

CVE-2017-5205

Buffer overflow in parser.

CVE-2017-5341

Buffer overflow in parser.

CVE-2017-5342

Buffer overflow in parser.

CVE-2017-5482

Buffer overflow in parser.

CVE-2017-5483

Buffer overflow in parser.

CVE-2017-5484

Buffer overflow in parser.

CVE-2017-5485

Buffer overflow in parser.

CVE-2017-5486

Buffer overflow in parser.

For Debian 7 'Wheezy', these problems have been fixed in version
4.9.0-1~deb7u1.

We recommend that you upgrade your tcpdump packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tcpdump"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected tcpdump package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"tcpdump", reference:"4.9.0-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
