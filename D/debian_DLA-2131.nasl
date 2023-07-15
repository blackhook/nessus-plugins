#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2131-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134182);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-6262");
  script_bugtraq_id(71540);

  script_name(english:"Debian DLA-2131-2 : rrdtool regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a regression in a previous fix, which
resulted in the following error :

ERROR: cannot compile regular expression: Error while compiling
regular expression ^(?:[^%]+|%%)*%[+-
0#]?[0-9]*([.][0-9]+)?l[eEfF](?:[^%]+|%%)*%s(?:[^%]+|%%)*$ at char 18:
range out of order in character class (^(?:[^%]+|%%)*%[+-
0#]?[0-9]*([.][0-9]+)?l[eEfF](?:[^%]+|%%)*%s(?:[^%]+|%%)*$)

For Debian 8 'Jessie', this problem has been fixed in version
1.4.8-1.2+deb8u2.

We recommend that you upgrade your rrdtool packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/rrdtool"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblua5.1-rrd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblua5.1-rrd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librrd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librrd-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librrd-ruby1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librrd-ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librrd4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librrdp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librrds-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rrdcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rrdtool-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rrdtool-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-rrd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");
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
if (deb_check(release:"8.0", prefix:"liblua5.1-rrd-dev", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"liblua5.1-rrd0", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"librrd-dev", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"librrd-ruby", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"librrd-ruby1.8", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"librrd-ruby1.9.1", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"librrd4", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"librrdp-perl", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"librrds-perl", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-rrdtool", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"rrdcached", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"rrdtool", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"rrdtool-dbg", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"rrdtool-tcl", reference:"1.4.8-1.2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-rrd", reference:"1.4.8-1.2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
