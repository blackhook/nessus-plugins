#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1297-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107105);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-7435", "CVE-2018-7436", "CVE-2018-7437", "CVE-2018-7438", "CVE-2018-7439");

  script_name(english:"Debian DLA-1297-1 : freexl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Leon reported five heap-based buffer-overflow vulnerabilities in
FreeXL.

CVE-2018-7435

There is a heap-based buffer over-read in the freexl::destroy_cell
function.

CVE-2018-7436

There is a heap-based buffer over-read in a pointer dereference of the
parse_SST function.

CVE-2018-7437

There is a heap-based buffer over-read in a memcpy call of the
parse_SST function.

CVE-2018-7438

There is a heap-based buffer over-read in the parse_unicode_string
function.

CVE-2018-7439

There is a heap-based buffer over-read in the function
read_mini_biff_next_record.

For Debian 7 'Wheezy', these problems have been fixed in version
1.0.0b-1+deb7u5.

We recommend that you upgrade your freexl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/freexl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreexl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreexl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreexl1-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"libfreexl-dev", reference:"1.0.0b-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libfreexl1", reference:"1.0.0b-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libfreexl1-dbg", reference:"1.0.0b-1+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
