#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(107109);
  script_version("3.3");
  script_cvs_date("Date: 2019/03/12  9:14:55");

  script_cve_id("CVE-2017-12562", "CVE-2017-14634", "CVE-2017-8361", "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8365");

  script_name(english:"FreeBSD : libsndfile -- multiple vulnerabilities (2b386075-1d9c-11e8-b6aa-4ccc6adda413)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Agostino Sarubbo, Gentoo reports :

CVE-2017-8361 (Medium): The flac_buffer_copy function in flac.c in
libsndfile 1.0.28 allows remote attackers to cause a denial of service
(buffer overflow and application crash) or possibly have unspecified
other impact via a crafted audio file.

CVE-2017-8362 (Medium): The flac_buffer_copy function in flac.c in
libsndfile 1.0.28 allows remote attackers to cause a denial of service
(invalid read and application crash) via a crafted audio file.

CVE-2017-8363 (Medium): The flac_buffer_copy function in flac.c in
libsndfile 1.0.28 allows remote attackers to cause a denial of service
(heap-based buffer over-read and application crash) via a crafted
audio file.

CVE-2017-8365 (Medium): The i2les_array function in pcm.c in
libsndfile 1.0.28 allows remote attackers to cause a denial of service
(buffer over-read and application crash) via a crafted audio file.

manxorist on Github reports :

CVE-2017-12562 (High): Heap-based Buffer Overflow in the
psf_binheader_writef function in common.c in libsndfile through 1.0.28
allows remote attackers to cause a denial of service (application
crash) or possibly have unspecified other impact.

Xin-Jiang on Github reports :

CVE-2017-14634 (Medium): In libsndfile 1.0.28, a divide-by-zero error
exists in the function double64_init() in double64.c, which may lead
to DoS when playing a crafted audio file."
  );
  # https://blogs.gentoo.org/ago/2017/04/29/libsndfile-global-buffer-overflow-in-flac_buffer_copy-flac-c/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?575e0047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/issues/232"
  );
  # https://github.com/erikd/libsndfile/commit/fd0484aba8e51d16af1e3a880f9b8b857b385eb3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a0d9177"
  );
  # https://blogs.gentoo.org/ago/2017/04/29/libsndfile-invalid-memory-read-in-flac_buffer_copy-flac-c/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c971ff39"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/issues/231"
  );
  # https://github.com/erikd/libsndfile/commit/ef1dbb2df1c0e741486646de40bd638a9c4cd808
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95e7d37a"
  );
  # https://blogs.gentoo.org/ago/2017/04/29/libsndfile-heap-based-buffer-overflow-in-flac_buffer_copy-flac-c/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b1b1b20"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/issues/233"
  );
  # https://github.com/erikd/libsndfile/commit/fd0484aba8e51d16af1e3a880f9b8b857b385eb3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a0d9177"
  );
  # https://github.com/erikd/libsndfile/commit/cd7da8dbf6ee4310d21d9e44b385d6797160d9e8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82a0d72b"
  );
  # https://blogs.gentoo.org/ago/2017/04/29/libsndfile-global-buffer-overflow-in-i2les_array-pcm-c/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?53801b81"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/issues/230"
  );
  # https://github.com/erikd/libsndfile/commit/fd0484aba8e51d16af1e3a880f9b8b857b385eb3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a0d9177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/issues/292/"
  );
  # https://github.com/erikd/libsndfile/commit/cf7a8182c2642c50f1cf90dddea9ce96a8bad2e8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc3e5377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/erikd/libsndfile/issues/318"
  );
  # https://github.com/erikd/libsndfile/commit/85c877d5072866aadbe8ed0c3e0590fbb5e16788
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4058f18b"
  );
  # https://vuxml.freebsd.org/freebsd/2b386075-1d9c-11e8-b6aa-4ccc6adda413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?320a87f9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libsndfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-libsndfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c7-libsndfile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"libsndfile<1.0.28_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-libsndfile<1.0.28_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-libsndfile<1.0.28_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
