#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3832. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99545);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-5373", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5378", "CVE-2017-5380", "CVE-2017-5383", "CVE-2017-5390", "CVE-2017-5396", "CVE-2017-5398", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410");
  script_xref(name:"DSA", value:"3832");

  script_name(english:"Debian DSA-3832-1 : icedove - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in Thunderbird, which may may
lead to the execution of arbitrary code or information leaks.

With this update, the Icedove packages are de-branded back to the
official Mozilla branding. With the removing of the Debian branding
the packages are also renamed back to the official names used by
Mozilla.

The Thunderbird package is using a different default profile folder,
the default profile folder is now '\$(HOME)/.thunderbird'. The users
profile folder, that was used in Icedove, will get migrated to the new
profile folder on the first start, that can take a little bit more
time.

Please read README.Debian for getting more information about the
changes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3832"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (jessie), these problems have been fixed
in version 1:45.8.0-3~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
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
if (deb_check(release:"8.0", prefix:"calendar-google-provider", reference:"1:45.8.0-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove", reference:"1:45.8.0-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove-dbg", reference:"1:45.8.0-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"icedove-dev", reference:"1:45.8.0-3~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"iceowl-extension", reference:"1:45.8.0-3~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
