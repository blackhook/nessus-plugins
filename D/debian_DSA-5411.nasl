#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5411. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176432);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/27");

  script_cve_id(
    "CVE-2020-35980",
    "CVE-2021-4043",
    "CVE-2021-21852",
    "CVE-2021-33361",
    "CVE-2021-33363",
    "CVE-2021-33364",
    "CVE-2021-33365",
    "CVE-2021-33366",
    "CVE-2021-36412",
    "CVE-2021-36414",
    "CVE-2021-36417",
    "CVE-2021-40559",
    "CVE-2021-40562",
    "CVE-2021-40563",
    "CVE-2021-40564",
    "CVE-2021-40565",
    "CVE-2021-40566",
    "CVE-2021-40567",
    "CVE-2021-40568",
    "CVE-2021-40569",
    "CVE-2021-40570",
    "CVE-2021-40571",
    "CVE-2021-40572",
    "CVE-2021-40574",
    "CVE-2021-40575",
    "CVE-2021-40576",
    "CVE-2021-40592",
    "CVE-2021-40606",
    "CVE-2021-40608",
    "CVE-2021-40609",
    "CVE-2021-40944",
    "CVE-2021-41456",
    "CVE-2021-41457",
    "CVE-2021-41459",
    "CVE-2021-45262",
    "CVE-2021-45263",
    "CVE-2021-45267",
    "CVE-2021-45291",
    "CVE-2021-45292",
    "CVE-2021-45297",
    "CVE-2021-45760",
    "CVE-2021-45762",
    "CVE-2021-45763",
    "CVE-2021-45764",
    "CVE-2021-45767",
    "CVE-2021-45831",
    "CVE-2021-46038",
    "CVE-2021-46039",
    "CVE-2021-46040",
    "CVE-2021-46041",
    "CVE-2021-46042",
    "CVE-2021-46043",
    "CVE-2021-46044",
    "CVE-2021-46045",
    "CVE-2021-46046",
    "CVE-2021-46047",
    "CVE-2021-46049",
    "CVE-2021-46051",
    "CVE-2022-1035",
    "CVE-2022-1222",
    "CVE-2022-1441",
    "CVE-2022-1795",
    "CVE-2022-2454",
    "CVE-2022-3222",
    "CVE-2022-3957",
    "CVE-2022-4202",
    "CVE-2022-24574",
    "CVE-2022-24577",
    "CVE-2022-24578",
    "CVE-2022-26967",
    "CVE-2022-27145",
    "CVE-2022-27147",
    "CVE-2022-29537",
    "CVE-2022-36190",
    "CVE-2022-36191",
    "CVE-2022-38530",
    "CVE-2022-43255",
    "CVE-2022-45202",
    "CVE-2022-45283",
    "CVE-2022-45343",
    "CVE-2022-47086",
    "CVE-2022-47091",
    "CVE-2022-47094",
    "CVE-2022-47095",
    "CVE-2022-47657",
    "CVE-2022-47659",
    "CVE-2022-47660",
    "CVE-2022-47661",
    "CVE-2022-47662",
    "CVE-2022-47663",
    "CVE-2023-0770",
    "CVE-2023-0818",
    "CVE-2023-0819",
    "CVE-2023-0866",
    "CVE-2023-1448",
    "CVE-2023-1449",
    "CVE-2023-1452",
    "CVE-2023-1654",
    "CVE-2023-2837",
    "CVE-2023-2838",
    "CVE-2023-2839",
    "CVE-2023-2840",
    "CVE-2023-23143",
    "CVE-2023-23144",
    "CVE-2023-23145"
  );

  script_name(english:"Debian DSA-5411-1 : gpac - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5411 advisory.

  - An issue was discovered in GPAC version 0.8.0 and 1.0.1. There is a use-after-free in the function
    gf_isom_box_del() in isomedia/box_funcs.c. (CVE-2020-35980)

  - Multiple exploitable integer overflow vulnerabilities exist within the MPEG-4 decoding functionality of
    the GPAC Project on Advanced Content library v1.0.1. A specially crafted MPEG-4 input at stss decoder
    can cause an integer overflow due to unchecked arithmetic resulting in a heap-based buffer overflow that
    causes memory corruption. An attacker can convince a user to open a video to trigger this vulnerability.
    (CVE-2021-21852)

  - Memory leak in the afra_box_read function in MP4Box in GPAC 1.0.1 allows attackers to read memory via a
    crafted file. (CVE-2021-33361)

  - Memory leak in the infe_box_read function in MP4Box in GPAC 1.0.1 allows attackers to read memory via a
    crafted file. (CVE-2021-33363)

  - Memory leak in the def_parent_box_new function in MP4Box in GPAC 1.0.1 allows attackers to read memory via
    a crafted file. (CVE-2021-33364)

  - Memory leak in the gf_isom_get_root_od function in MP4Box in GPAC 1.0.1 allows attackers to read memory
    via a crafted file. (CVE-2021-33365)

  - Memory leak in the gf_isom_oinf_read_entry function in MP4Box in GPAC 1.0.1 allows attackers to read
    memory via a crafted file. (CVE-2021-33366)

  - A heap-based buffer overflow vulnerability exists in MP4Box in GPAC 1.0.1 via the
    gp_rtp_builder_do_mpeg12_video function, which allows attackers to possibly have unspecified other impact
    via a crafted file in the MP4Box command, (CVE-2021-36412)

  - A heab-based buffer overflow vulnerability exists in MP4Box in GPAC 1.0.1 via media.c, which allows
    attackers to cause a denial of service or execute arbitrary code via a crafted file. (CVE-2021-36414)

  - A heap-based buffer overflow vulnerability exists in GPAC v1.0.1 in the gf_isom_dovi_config_get function
    in MP4Box, which causes a denial of service or execute arbitrary code via a crafted file. (CVE-2021-36417)

  - NULL Pointer Dereference in GitHub repository gpac/gpac prior to 1.1.0. (CVE-2021-4043)

  - A null pointer deference vulnerability exists in gpac through 1.0.1 via the naludmx_parse_nal_avc function
    in reframe_nalu, which allows a denail of service. (CVE-2021-40559)

  - A Segmentation fault caused by a floating point exception exists in Gpac through 1.0.1 using mp4box via
    the naludmx_enqueue_or_dispatch function in reframe_nalu.c, which causes a denial of service.
    (CVE-2021-40562)

  - A Segmentation fault exists casued by null pointer dereference exists in Gpac through 1.0.1 via the
    naludmx_create_avc_decoder_config function in reframe_nalu.c when using mp4box, which causes a denial of
    service. (CVE-2021-40563)

  - A Segmentation fault caused by null pointer dereference vulnerability eists in Gpac through 1.0.2 via the
    avc_parse_slice function in av_parsers.c when using mp4box, which causes a denial of service.
    (CVE-2021-40564)

  - A Segmentation fault caused by a null pointer dereference vulnerability exists in Gpac through 1.0.1 via
    the gf_avc_parse_nalu function in av_parsers.c when using mp4box, which causes a denial of service.
    (CVE-2021-40565)

  - A Segmentation fault casued by heap use after free vulnerability exists in Gpac through 1.0.1 via the
    mpgviddmx_process function in reframe_mpgvid.c when using mp4box, which causes a denial of service.
    (CVE-2021-40566)

  - Segmentation fault vulnerability exists in Gpac through 1.0.1 via the gf_odf_size_descriptor function in
    desc_private.c when using mp4box, which causes a denial of service. (CVE-2021-40567)

  - A buffer overflow vulnerability exists in Gpac through 1.0.1 via a malformed MP4 file in the
    svc_parse_slice function in av_parsers.c, which allows attackers to cause a denial of service, even code
    execution and escalation of privileges. (CVE-2021-40568)

  - The binary MP4Box in Gpac through 1.0.1 has a double-free vulnerability in the iloc_entry_del funciton in
    box_code_meta.c, which allows attackers to cause a denial of service. (CVE-2021-40569)

  - The binary MP4Box in Gpac 1.0.1 has a double-free vulnerability in the avc_compute_poc function in
    av_parsers.c, which allows attackers to cause a denial of service, even code execution and escalation of
    privileges. (CVE-2021-40570)

  - The binary MP4Box in Gpac 1.0.1 has a double-free vulnerability in the ilst_box_read function in
    box_code_apple.c, which allows attackers to cause a denial of service, even code execution and escalation
    of privileges. (CVE-2021-40571)

  - The binary MP4Box in Gpac 1.0.1 has a double-free bug in the av1dmx_finalize function in reframe_av1.c,
    which allows attackers to cause a denial of service. (CVE-2021-40572)

  - The binary MP4Box in Gpac 1.0.1 has a double-free vulnerability in the gf_text_get_utf8_line function in
    load_text.c, which allows attackers to cause a denial of service, even code execution and escalation of
    privileges. (CVE-2021-40574)

  - The binary MP4Box in Gpac 1.0.1 has a null pointer dereference vulnerability in the mpgviddmx_process
    function in reframe_mpgvid.c, which allows attackers to cause a denial of service. This vulnerability is
    possibly due to an incomplete fix for CVE-2021-40566. (CVE-2021-40575)

  - The binary MP4Box in Gpac 1.0.1 has a null pointer dereference vulnerability in the gf_isom_get_payt_count
    function in hint_track.c, which allows attackers to cause a denial of service. (CVE-2021-40576)

  - GPAC version before commit 71460d72ec07df766dab0a4d52687529f3efcf0a (version v1.0.1 onwards) contains loop
    with unreachable exit condition ('infinite loop') vulnerability in ISOBMFF reader filter, isoffin_read.c.
    Function isoffin_process() can result in DoS by infinite loop. To exploit, the victim must open a
    specially crafted mp4 file. (CVE-2021-40592)

  - The gf_bs_write_data function in GPAC 1.0.1 allows attackers to cause a denial of service via a crafted
    file in the MP4Box command. (CVE-2021-40606)

  - The gf_hinter_track_finalize function in GPAC 1.0.1 allows attackers to cause a denial of service via a
    crafted file in the MP4Box command. (CVE-2021-40608)

  - The GetHintFormat function in GPAC 1.0.1 allows attackers to cause a denial of service via a crafted file
    in the MP4Box command. (CVE-2021-40609)

  - In GPAC MP4Box 1.1.0, there is a Null pointer reference in the function gf_filter_pid_get_packet function
    in src/filter_core/filter_pid.c:5394, as demonstrated by GPAC. This can cause a denial of service (DOS).
    (CVE-2021-40944)

  - There is a stack buffer overflow in MP4Box v1.0.1 at src/filters/dmx_nhml.c:1004 in the
    nhmldmx_send_sample() function szXmlTo parameter which leads to a denial of service vulnerability.
    (CVE-2021-41456)

  - There is a stack buffer overflow in MP4Box 1.1.0 at src/filters/dmx_nhml.c in nhmldmx_init_parsing which
    leads to a denial of service vulnerability. (CVE-2021-41457)

  - There is a stack buffer overflow in MP4Box v1.0.1 at src/filters/dmx_nhml.c:1008 in the
    nhmldmx_send_sample() function szXmlFrom parameter which leads to a denial of service vulnerability.
    (CVE-2021-41459)

  - An invalid free vulnerability exists in gpac 1.1.0 via the gf_sg_command_del function, which causes a
    segmentation fault and application crash. (CVE-2021-45262)

  - An invalid free vulnerability exists in gpac 1.1.0 via the gf_svg_delete_attribute_value function, which
    causes a segmentation fault and application crash. (CVE-2021-45263)

  - An invalid memory address dereference vulnerability exists in gpac 1.1.0 via the svg_node_start function,
    which causes a segmentation fault and application crash. (CVE-2021-45267)

  - The gf_dump_setup function in GPAC 1.0.1 allows malicoius users to cause a denial of service (Invalid
    memory address dereference) via a crafted file in the MP4Box command. (CVE-2021-45291)

  - The gf_isom_hint_rtp_read function in GPAC 1.0.1 allows attackers to cause a denial of service (Invalid
    memory address dereference) via a crafted file in the MP4Box command. (CVE-2021-45292)

  - An infinite loop vulnerability exists in Gpac 1.0.1 in gf_get_bit_size. (CVE-2021-45297)

  - GPAC v1.1.0 was discovered to contain an invalid memory address dereference via the function
    gf_list_last(). This vulnerability allows attackers to cause a Denial of Service (DoS). (CVE-2021-45760)

  - GPAC v1.1.0 was discovered to contain an invalid memory address dereference via the function
    gf_sg_vrml_mf_reset(). This vulnerability allows attackers to cause a Denial of Service (DoS).
    (CVE-2021-45762)

  - GPAC v1.1.0 was discovered to contain an invalid call in the function gf_node_changed(). This
    vulnerability can lead to a Denial of Service (DoS). (CVE-2021-45763)

  - GPAC v1.1.0 was discovered to contain an invalid memory address dereference via the function
    shift_chunk_offsets.isra(). (CVE-2021-45764)

  - GPAC 1.1.0 was discovered to contain an invalid memory address dereference via the function lsr_read_id().
    This vulnerability can lead to a Denial of Service (DoS). (CVE-2021-45767)

  - A Null Pointer Dereference vulnerability exitgs in GPAC 1.0.1 in MP4Box via __strlen_avx2, which causes a
    Denial of Service. (CVE-2021-45831)

  - A Pointer Dereference vulnerability exists in GPAC 1.0.1 in unlink_chunk.isra, which causes a Denial of
    Service (context-dependent). (CVE-2021-46038)

  - A Pointer Dereference Vulnerabilty exists in GPAC 1.0.1 via the shift_chunk_offsets.part function, which
    causes a Denial of Service (context-dependent). (CVE-2021-46039)

  - A Pointer Dereference Vulnerabilty exists in GPAC 1.0.1 via the finplace_shift_moov_meta_offsets function,
    which causes a Denial of Servie (context-dependent). (CVE-2021-46040)

  - A Segmentation Fault Vulnerability exists in GPAC 1.0.1 via the co64_box_new function, which causes a
    Denial of Service. (CVE-2021-46041)

  - A Pointer Dereference Vulnerability exists in GPAC 1.0.1 via the _fseeko function, which causes a Denial
    of Service. (CVE-2021-46042)

  - A Pointer Dereference Vulnerability exits in GPAC 1.0.1 in the gf_list_count function, which causes a
    Denial of Service. (CVE-2021-46043)

  - A Pointer Dereference Vulnerabilty exists in GPAC 1.0.1via ShiftMetaOffset.isra, which causes a Denial of
    Service (context-dependent). (CVE-2021-46044)

  - GPAC 1.0.1 is affected by: Abort failed. The impact is: cause a denial of service (context-dependent).
    (CVE-2021-46045)

  - A Pointer Derefernce Vulnerbility exists GPAC 1.0.1 the gf_isom_box_size function, which could cause a
    Denial of Service (context-dependent). (CVE-2021-46046)

  - A Pointer Dereference Vulnerability exists in GPAC 1.0.1 via the gf_hinter_finalize function.
    (CVE-2021-46047)

  - A Pointer Dereference Vulnerability exists in GPAC 1.0.1 via the gf_fileio_check function, which could
    cause a Denial of Service. (CVE-2021-46049)

  - A Pointer Dereference Vulnerability exists in GPAC 1.0.1 via the Media_IsSelfContained function, which
    could cause a Denial of Service. . (CVE-2021-46051)

  - Segmentation Fault caused by MP4Box -lsr in GitHub repository gpac/gpac prior to 2.1.0-DEV.
    (CVE-2022-1035)

  - Inf loop in GitHub repository gpac/gpac prior to 2.1.0-DEV. (CVE-2022-1222)

  - MP4Box is a component of GPAC-2.0.0, which is a widely-used third-party package on RPM Fusion. When MP4Box
    tries to parse a MP4 file, it calls the function `diST_box_read()` to read from video. In this function,
    it allocates a buffer `str` with fixed length. However, content read from `bs` is controllable by user, so
    is the length, which causes a buffer overflow. (CVE-2022-1441)

  - Use After Free in GitHub repository gpac/gpac prior to v2.1.0-DEV. (CVE-2022-1795)

  - Integer Overflow or Wraparound in GitHub repository gpac/gpac prior to 2.1-DEV. (CVE-2022-2454)

  - GPAC 1.0.1 is affected by a NULL pointer dereference in gf_dump_vrml_field.isra (). (CVE-2022-24574)

  - GPAC 1.0.1 is affected by a NULL pointer dereference in gf_utf8_wcslen. (gf_utf8_wcslen is a renamed
    Unicode utf8_wcslen function.) (CVE-2022-24577)

  - GPAC 1.0.1 is affected by a heap-based buffer overflow in SFS_AddString () at bifs/script_dec.c.
    (CVE-2022-24578)

  - GPAC 2.0 allows a heap-based buffer overflow in gf_base64_encode. It can be triggered via MP4Box.
    (CVE-2022-26967)

  - GPAC mp4box 1.1.0-DEV-rev1727-g8be34973d-master has a stack-overflow vulnerability in function
    gf_isom_get_sample_for_movie_time of mp4box. (CVE-2022-27145)

  - GPAC mp4box 1.1.0-DEV-rev1727-g8be34973d-master has a use-after-free vulnerability in function
    gf_node_get_attribute_by_tag. (CVE-2022-27147)

  - gp_rtp_builder_do_hevc in ietf/rtp_pck_mpeg4.c in GPAC 2.0.0 has a heap-based buffer over-read, as
    demonstrated by MP4Box. (CVE-2022-29537)

  - Uncontrolled Recursion in GitHub repository gpac/gpac prior to 2.1.0-DEV. (CVE-2022-3222)

  - GPAC mp4box 2.1-DEV-revUNKNOWN-master has a use-after-free vulnerability in function
    gf_isom_dovi_config_get. This vulnerability was fixed in commit fef6242. (CVE-2022-36190)

  - A heap-buffer-overflow had occurred in function gf_isom_dovi_config_get of isomedia/avc_ext.c:2490, as
    demonstrated by MP4Box. This vulnerability was fixed in commit fef6242. (CVE-2022-36191)

  - GPAC v2.1-DEV-rev232-gfcaa01ebb-master was discovered to contain a stack overflow when processing
    ISOM_IOD. (CVE-2022-38530)

  - A vulnerability classified as problematic was found in GPAC. Affected by this vulnerability is the
    function svg_parse_preserveaspectratio of the file scenegraph/svg_attributes.c of the component SVG
    Parser. The manipulation leads to memory leak. The attack can be launched remotely. The name of the patch
    is 2191e66aa7df750e8ef01781b1930bea87b713bb. It is recommended to apply a patch to fix this issue. The
    associated identifier of this vulnerability is VDB-213463. (CVE-2022-3957)

  - A vulnerability, which was classified as problematic, was found in GPAC 2.1-DEV-rev490-g68064e101-master.
    Affected is the function lsr_translate_coords of the file laser/lsr_dec.c. The manipulation leads to
    integer overflow. It is possible to launch the attack remotely. The exploit has been disclosed to the
    public and may be used. The name of the patch is b3d821c4ae9ba62b3a194d9dcb5e99f17bd56908. It is
    recommended to apply a patch to fix this issue. VDB-214518 is the identifier assigned to this
    vulnerability. (CVE-2022-4202)

  - GPAC v2.1-DEV-rev368-gfd054169b-master was discovered to contain a memory leak via the component
    gf_odf_new_iod at odf/odf_code.c. (CVE-2022-43255)

  - GPAC v2.1-DEV-rev428-gcb8ae46c8-master was discovered to contain a stack overflow via the function
    dimC_box_read at isomedia/box_code_3gpp.c. (CVE-2022-45202)

  - GPAC MP4box v2.0.0 was discovered to contain a stack overflow in the smil_parse_time_list parameter at
    /scenegraph/svg_attributes.c. (CVE-2022-45283)

  - GPAC v2.1-DEV-rev478-g696e6f868-master was discovered to contain a heap use-after-free via the Q_IsTypeOn
    function at /gpac/src/bifs/unquantize.c. (CVE-2022-45343)

  - GPAC MP4Box v2.1-DEV-rev574-g9d5bb184b contains a segmentation violation via the function
    gf_sm_load_init_swf at scene_manager/swf_parse.c (CVE-2022-47086)

  - GPAC MP4box 2.1-DEV-rev574-g9d5bb184b is vulnerable to Buffer Overflow in gf_text_process_sub function of
    filters/load_text.c (CVE-2022-47091)

  - GPAC MP4box 2.1-DEV-rev574-g9d5bb184b is vulnerable to Null pointer dereference via filters/dmx_m2ts.c:343
    in m2tsdmx_declare_pid (CVE-2022-47094)

  - GPAC MP4box 2.1-DEV-rev574-g9d5bb184b is vulnerable to Buffer overflow in hevc_parse_vps_extension
    function of media_tools/av_parsers.c (CVE-2022-47095)

  - GPAC MP4Box 2.1-DEV-rev644-g5c4df2a67 is vulnerable to buffer overflow in function
    hevc_parse_vps_extension of media_tools/av_parsers.c:7662 (CVE-2022-47657)

  - GPAC MP4box 2.1-DEV-rev644-g5c4df2a67 is vulnerable to Buffer Overflow in gf_bs_read_data (CVE-2022-47659)

  - GPAC MP4Box 2.1-DEV-rev644-g5c4df2a67 is has an integer overflow in isomedia/isom_write.c (CVE-2022-47660)

  - GPAC MP4Box 2.1-DEV-rev649-ga8f438d20 is vulnerable to Buffer Overflow via media_tools/av_parsers.c:4988
    in gf_media_nalu_add_emulation_bytes (CVE-2022-47661)

  - GPAC MP4Box 2.1-DEV-rev649-ga8f438d20 has a segment fault (/stack overflow) due to infinite recursion in
    Media_GetSample isomedia/media.c:662 (CVE-2022-47662)

  - GPAC MP4box 2.1-DEV-rev649-ga8f438d20 is vulnerable to buffer overflow in h263dmx_process
    filters/reframe_h263.c:609 (CVE-2022-47663)

  - Stack-based Buffer Overflow in GitHub repository gpac/gpac prior to 2.2. (CVE-2023-0770)

  - Off-by-one Error in GitHub repository gpac/gpac prior to v2.3.0-DEV. (CVE-2023-0818)

  - Heap-based Buffer Overflow in GitHub repository gpac/gpac prior to v2.3.0-DEV. (CVE-2023-0819)

  - Heap-based Buffer Overflow in GitHub repository gpac/gpac prior to 2.3.0-DEV. (CVE-2023-0866)

  - A vulnerability, which was classified as problematic, was found in GPAC 2.3-DEV-rev35-gbbca86917-master.
    This affects the function gf_m2ts_process_sdt of the file media_tools/mpegts.c. The manipulation leads to
    heap-based buffer overflow. Attacking locally is a requirement. The exploit has been disclosed to the
    public and may be used. It is recommended to apply a patch to fix this issue. The identifier VDB-223293
    was assigned to this vulnerability. (CVE-2023-1448)

  - A vulnerability has been found in GPAC 2.3-DEV-rev35-gbbca86917-master and classified as problematic. This
    vulnerability affects the function gf_av1_reset_state of the file media_tools/av_parsers.c. The
    manipulation leads to double free. It is possible to launch the attack on the local host. The exploit has
    been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue.
    VDB-223294 is the identifier assigned to this vulnerability. (CVE-2023-1449)

  - A vulnerability was found in GPAC 2.3-DEV-rev35-gbbca86917-master. It has been declared as critical.
    Affected by this vulnerability is an unknown functionality of the file filters/load_text.c. The
    manipulation leads to buffer overflow. Local access is required to approach this attack. The exploit has
    been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue. The
    identifier VDB-223297 was assigned to this vulnerability. (CVE-2023-1452)

  - Denial of Service in GitHub repository gpac/gpac prior to 2.4.0. (CVE-2023-1654)

  - Buffer overflow vulnerability in function avc_parse_slice in file media_tools/av_parsers.c. GPAC version
    2.3-DEV-rev1-g4669ba229-master. (CVE-2023-23143)

  - Integer overflow vulnerability in function Q_DecCoordOnUnitSphere file bifs/unquantize.c in GPAC version
    2.2-rev0-gab012bbfb-master. (CVE-2023-23144)

  - GPAC version 2.2-rev0-gab012bbfb-master was discovered to contain a memory leak in lsr_read_rare_full
    function. (CVE-2023-23145)

  - Stack-based Buffer Overflow in GitHub repository gpac/gpac prior to 2.2.2. (CVE-2023-2837)

  - Out-of-bounds Read in GitHub repository gpac/gpac prior to 2.2.2. (CVE-2023-2838)

  - Divide By Zero in GitHub repository gpac/gpac prior to 2.2.2. (CVE-2023-2839)

  - NULL Pointer Dereference in GitHub repository gpac/gpac prior to 2.2.2. (CVE-2023-2840)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/gpac");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5411");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35980");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21852");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33361");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33363");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33364");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33365");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33366");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36412");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36414");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36417");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4043");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40559");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40562");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40563");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40564");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40565");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40566");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40567");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40568");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40569");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40570");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40571");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40572");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40574");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40575");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40576");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40592");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40606");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40609");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-40944");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41456");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41457");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41459");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45262");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45263");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45267");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45291");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45292");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45297");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45762");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45767");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45831");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46038");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46039");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46041");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46043");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46044");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46045");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46046");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46047");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46049");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46051");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1035");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1441");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24574");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24577");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24578");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26967");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27147");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29537");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36190");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36191");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38530");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3957");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4202");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-43255");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45202");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45343");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47086");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47091");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47094");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47095");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47657");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47659");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47660");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47661");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0770");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0818");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0819");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0866");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1448");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1449");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1452");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-1654");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23143");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23145");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2837");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2838");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2839");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-2840");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/gpac");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gpac packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.0.1+dfsg1-4+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1795");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2840");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gpac-modules-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgpac-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgpac10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'gpac', 'reference': '1.0.1+dfsg1-4+deb11u2'},
    {'release': '11.0', 'prefix': 'gpac-modules-base', 'reference': '1.0.1+dfsg1-4+deb11u2'},
    {'release': '11.0', 'prefix': 'libgpac-dev', 'reference': '1.0.1+dfsg1-4+deb11u2'},
    {'release': '11.0', 'prefix': 'libgpac10', 'reference': '1.0.1+dfsg1-4+deb11u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gpac / gpac-modules-base / libgpac-dev / libgpac10');
}
