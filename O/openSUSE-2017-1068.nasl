#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1068.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103290);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11399", "CVE-2017-14054", "CVE-2017-14055", "CVE-2017-14056", "CVE-2017-14057", "CVE-2017-14058", "CVE-2017-14059", "CVE-2017-14169", "CVE-2017-14170", "CVE-2017-14171", "CVE-2017-14222", "CVE-2017-14223", "CVE-2017-14225");

  script_name(english:"openSUSE Security Update : ffmpeg / ffmpeg2 (openSUSE-2017-1068)");
  script_summary(english:"Check for the openSUSE-2017-1068 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update introduces lame and twolame.

For ffmpeg2 it updates to version 2.8.13 and fixes several issues.

These security issues were fixed :

  - CVE-2017-14058: The read_data function in
    libavformat/hls.c did not restrict reload attempts for
    an insufficient list, which allowed remote attackers to
    cause a denial of service (infinite loop) (bsc#1056762)

  - CVE-2017-14057: In asf_read_marker() due to lack of an
    EOF (End of File) check might have caused huge CPU and
    memory consumption. When a crafted ASF file, which
    claims a large 'name_len' or 'count' field in the header
    but did not contain sufficient backing data, was
    provided, the loops over the name and markers would
    consume huge CPU and memory resources, since there is no
    EOF check inside these loops (bsc#1056761)

  - CVE-2017-14059: A DoS in cine_read_header() due to lack
    of an EOF check might have caused huge CPU and memory
    consumption. When a crafted CINE file, which claims a
    large 'duration' field in the header but did not contain
    sufficient backing data, was provided, the image-offset
    parsing loop would consume huge CPU and memory
    resources, since there is no EOF check inside the loop
    (bsc#1056763)

  - CVE-2017-14056: A DoS in rl2_read_header() due to lack
    of an EOF (End of File) check might have caused huge CPU
    and memory consumption. When a crafted RL2 file, which
    claims a large 'frame_count' field in the header but did
    not contain sufficient backing data, was provided, the
    loops (for offset and size tables) would consume huge
    CPU and memory resources, since there is no EOF check
    inside these loops (bsc#1056760)

  - CVE-2017-14055: a DoS in mv_read_header() due to lack of
    an EOF (End of File) check might have caused huge CPU
    and memory consumption. When a crafted MV file, which
    claims a large 'nb_frames' field in the header but did
    not contain sufficient backing data, was provided, the
    loop over the frames would consume huge CPU and memory
    resources, since there is no EOF check inside the loop
    (bsc#1056766)

  - boo#1046211: Lots of integer overflow fixes

  - CVE-2017-14169: In the mxf_read_primer_pack function an
    integer signedness error have might occured when a
    crafted file, which claims a large 'item_num' field such
    as 0xffffffff, was provided. As a result, the variable
    'item_num' turns negative, bypassing the check for a
    large value (bsc#1057536)

  - CVE-2017-14170: Prevent DoS in
    mxf_read_index_entry_array() due to lack of an EOF (End
    of File) check that might have caused huge CPU
    consumption. When a crafted MXF file, which claims a
    large 'nb_index_entries' field in the header but did not
    contain sufficient backing data, was provided, the loop
    would consume huge CPU resources, since there was no EOF
    check inside the loop. Moreover, this big loop can be
    invoked multiple times if there is more than one
    applicable data segment in the crafted MXF file
    (bsc#1057537)

  - CVE-2017-14171: Prevent DoS in nsv_parse_NSVf_header()
    due to lack of an EOF (End of File) check taht might
    have caused huge CPU consumption. When a crafted NSV
    file, which claims a large 'table_entries_used' field in
    the header but did not contain sufficient backing data,
    was provided, the loop over 'table_entries_used' would
    consume huge CPU resources, since there was no EOF check
    inside the loop (bsc#1057539)

  - !: CVE-2017-14223: Prevent DoS in
    asf_build_simple_index() due to lack of an EOF (End of
    File) check that might have caused huge CPU consumption.
    When a crafted ASF file, which claims a large 'ict'
    field in the header but did not contain sufficient
    backing data, was provided, the for loop would consume
    huge CPU and memory resources, since there was no EOF
    check inside the loop (bsc#1058019)

  - !: CVE-2017-14222: Prevent DoS in read_tfra() due to
    lack of an EOF (End of File) check that might have
    caused huge CPU and memory consumption. When a crafted
    MOV file, which claims a large 'item_count' field in the
    header but did not contain sufficient backing data, was
    provided, the loop would consume huge CPU and memory
    resources, since there was no EOF check inside the loop
    (bsc#1058020)

These non-security issues were fixed :

  - Unconditionalize celt, ass, openjpeg, webp, libva,
    vdpau.

  - Build unconditionally with lame and twolame

For ffmpeg it updates to version 3.3.4 and fixes several issues.

These security issues were fixed :

  - CVE-2017-14058: The read_data function in
    libavformat/hls.c did not restrict reload attempts for
    an insufficient list, which allowed remote attackers to
    cause a denial of service (infinite loop) (bsc#1056762)

  - CVE-2017-14057: In asf_read_marker() due to lack of an
    EOF (End of File) check might have caused huge CPU and
    memory consumption. When a crafted ASF file, which
    claims a large 'name_len' or 'count' field in the header
    but did not contain sufficient backing data, was
    provided, the loops over the name and markers would
    consume huge CPU and memory resources, since there is no
    EOF check inside these loops (bsc#1056761)

  - CVE-2017-14059: A DoS in cine_read_header() due to lack
    of an EOF check might have caused huge CPU and memory
    consumption. When a crafted CINE file, which claims a
    large 'duration' field in the header but did not contain
    sufficient backing data, was provided, the image-offset
    parsing loop would consume huge CPU and memory
    resources, since there is no EOF check inside the loop
    (bsc#1056763)

  - CVE-2017-14054: A DoS in ivr_read_header() due to lack
    of an EOF (End of File) check might have caused huge CPU
    consumption. When a crafted IVR file, which claims a
    large 'len' field in the header but did not contain
    sufficient backing data, was provided, the first type==4
    loop would consume huge CPU resources, since there is no
    EOF check inside the loop (bsc#1056765)

  - CVE-2017-14056: A DoS in rl2_read_header() due to lack
    of an EOF (End of File) check might have caused huge CPU
    and memory consumption. When a crafted RL2 file, which
    claims a large 'frame_count' field in the header but did
    not contain sufficient backing data, was provided, the
    loops (for offset and size tables) would consume huge
    CPU and memory resources, since there is no EOF check
    inside these loops (bsc#1056760)

  - CVE-2017-14055: a DoS in mv_read_header() due to lack of
    an EOF (End of File) check might have caused huge CPU
    and memory consumption. When a crafted MV file, which
    claims a large 'nb_frames' field in the header but did
    not contain sufficient backing data, was provided, the
    loop over the frames would consume huge CPU and memory
    resources, since there is no EOF check inside the loop
    (bsc#1056766)

  - CVE-2017-11399: Integer overflow in the ape_decode_frame
    function allowed remote attackers to cause a denial of
    service (out-of-array access and application crash) or
    possibly have unspecified other impact via a crafted APE
    file (bsc#1049095)

  - CVE-2017-14171: Prevent DoS in nsv_parse_NSVf_header()
    due to lack of an EOF (End of File) check taht might
    have caused huge CPU consumption. When a crafted NSV
    file, which claims a large 'table_entries_used' field in
    the header but did not contain sufficient backing data,
    was provided, the loop over 'table_entries_used' would
    consume huge CPU resources, since there was no EOF check
    inside the loop (bsc#1057539)

  - CVE-2017-14170: Prevent DoS in
    mxf_read_index_entry_array() due to lack of an EOF (End
    of File) check that might have caused huge CPU
    consumption. When a crafted MXF file, which claims a
    large 'nb_index_entries' field in the header but did not
    contain sufficient backing data, was provided, the loop
    would consume huge CPU resources, since there was no EOF
    check inside the loop. Moreover, this big loop can be
    invoked multiple times if there is more than one
    applicable data segment in the crafted MXF file
    (bsc#1057537)

  - CVE-2017-14169: In the mxf_read_primer_pack function an
    integer signedness error have might occured when a
    crafted file, which claims a large 'item_num' field such
    as 0xffffffff, was provided. As a result, the variable
    'item_num' turns negative, bypassing the check for a
    large value (bsc#1057536)

  - CVE-2017-14225: The av_color_primaries_name function may
    have returned a NULL pointer depending on a value
    contained in a file, but callers did not anticipate
    this, leading to a NULL pointer dereference
    (bsc#1058018)

  - CVE-2017-14223: Prevent DoS in asf_build_simple_index()
    due to lack of an EOF (End of File) check that might
    have caused huge CPU consumption. When a crafted ASF
    file, which claims a large 'ict' field in the header but
    did not contain sufficient backing data, was provided,
    the for loop would consume huge CPU and memory
    resources, since there was no EOF check inside the loop
    (bsc#1058019)

  - CVE-2017-14222: Prevent DoS in read_tfra() due to lack
    of an EOF (End of File) check that might have caused
    huge CPU and memory consumption. When a crafted MOV
    file, which claims a large 'item_count' field in the
    header but did not contain sufficient backing data, was
    provided, the loop would consume huge CPU and memory
    resources, since there was no EOF check inside the loop
    (bsc#1058020)

It also includes various fixes for integer overflows and too-large bit
shifts that didn't receive a CVE.

These non-security issues were fixed :

  - Unconditionalize celt, ass, openjpeg, webp, netcdf,
    libva, vdpau.

  - Build unconditionally with lame and twolame

  - boo#1041794: Disable cuda extensions

  - Add additional checks to ensure MPEG is off"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1058020"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ffmpeg / ffmpeg2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ffmpeg2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame-mp3rtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lame-mp3rtp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavcodec57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavdevice57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavfilter6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat56-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavformat57-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavresample3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil54-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavutil55-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmp3lame0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc53-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpostproc54-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswresample2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libswscale4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtwolame-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtwolame0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtwolame0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtwolame0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtwolame0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:twolame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:twolame-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:twolame-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg-debugsource-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg2-debugsource-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ffmpeg2-devel-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"lame-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"lame-debuginfo-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"lame-debugsource-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"lame-mp3rtp-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"lame-mp3rtp-debuginfo-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec56-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec56-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec57-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavcodec57-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice56-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice56-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice57-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavdevice57-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter5-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter5-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter6-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavfilter6-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat56-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat56-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat57-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavformat57-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample2-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample2-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample3-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavresample3-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil54-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil54-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil55-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libavutil55-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmp3lame-devel-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmp3lame0-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmp3lame0-debuginfo-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc53-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc53-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc54-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libpostproc54-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample1-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample1-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample2-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswresample2-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale-devel-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale3-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale3-debuginfo-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale4-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libswscale4-debuginfo-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtwolame-devel-0.3.13-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtwolame0-0.3.13-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libtwolame0-debuginfo-0.3.13-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"twolame-0.3.13-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"twolame-debuginfo-0.3.13-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"twolame-debugsource-0.3.13-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavcodec56-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavcodec56-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavcodec57-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavcodec57-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavdevice56-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavdevice56-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavdevice57-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavdevice57-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavfilter5-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavfilter5-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavfilter6-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavfilter6-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavformat56-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavformat56-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavformat57-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavformat57-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavresample2-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavresample2-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavresample3-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavresample3-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavutil54-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavutil54-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavutil55-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libavutil55-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmp3lame0-32bit-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmp3lame0-debuginfo-32bit-3.99.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpostproc53-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpostproc53-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpostproc54-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libpostproc54-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswresample1-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswresample1-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswresample2-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswresample2-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswscale3-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswscale3-debuginfo-32bit-2.8.13-25.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswscale4-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libswscale4-debuginfo-32bit-3.3.4-6.16.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtwolame0-32bit-0.3.13-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libtwolame0-debuginfo-32bit-0.3.13-2.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / ffmpeg-debuginfo / ffmpeg-debugsource / libavcodec-devel / etc");
}
