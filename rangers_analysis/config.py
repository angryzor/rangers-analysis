from ida_nalt import retrieve_input_file_sha256
from ida_funcs import get_fchunk
from ida_ua import o_phrase, o_displ, o_reg
from rangers_analysis.lib.ua_data_extraction import find_insn_forward, track_values, decoded_insns_forward
from rangers_analysis.lib.iterators import find

rangers_analysis_config = None

def looks_like_instantiator_wars(f):
    return find_insn_forward(lambda d: d.mnem == 'call' and d.insn.Op1.addr in rangers_analysis_config['allocator_addresses'], f.start_ea, f.end_ea)

def looks_like_instantiator_rangers(f):
    # Our little tracing asm walker can't deal with multi-chunk functions, so just take the first chunk so it doesn't crash
    f = get_fchunk(f.start_ea)

    # Check if we try to read out the vtable of rcx, presumably the allocator.
    vtbl_res = find(
        lambda i: i[0].mnem == 'mov' and i[0].insn.Op1.type == o_reg and i[0].insn.Op2.type == o_phrase and i[0].insn.Op2.reg in i[1]['allocator'].regs,
        track_values({ 'allocator': 1 }, decoded_insns_forward(f.start_ea, f.end_ea))
    )
    if not vtbl_res: return False
    vtbl_insn, at_vtbl_insn_values = vtbl_res
    after_vtbl_insn_values = { **at_vtbl_insn_values, 'alloc_vtable': vtbl_insn.insn.Op1.reg }

    # See if we do a direct call on a displacement operand
    displ_call_res = find(
        lambda i: i[0].mnem == 'call' and i[0].insn.Op1.type == o_displ and i[0].insn.Op1.addr == 8 and i[0].insn.Op1.reg in i[1]['alloc_vtable'].regs and 1 in i[1]['allocator'].regs,
        track_values(after_vtbl_insn_values, decoded_insns_forward(vtbl_insn.ea + vtbl_insn.size, f.end_ea))
    )
    if displ_call_res: return True

    # Otherwise, see if we first read out the function pointer separately and then do a call on a register
    allocfn_res = find(
        lambda i: i[0].mnem == 'mov' and i[0].insn.Op1.type == o_reg and i[0].insn.Op2.type == o_displ and i[0].insn.Op2.addr == 8 and i[0].insn.Op2.reg in i[1]['alloc_vtable'].regs,
        track_values(after_vtbl_insn_values, decoded_insns_forward(vtbl_insn.ea + vtbl_insn.size, f.end_ea))
    )
    if not allocfn_res: return False
    allocfn_insn, at_allocfn_insn_values = allocfn_res
    after_allocfn_insn_values = { **at_allocfn_insn_values, 'allocfn': allocfn_insn.insn.Op1.reg }

    call_res = find(
        lambda i: i[0].mnem == 'call' and i[0].insn.Op1.type == o_reg and i[0].insn.Op1.reg in i[1]['allocfn'].regs and 1 in i[1]['allocator'].regs,
        track_values(after_allocfn_insn_values, decoded_insns_forward(allocfn_insn.ea + allocfn_insn.size, f.end_ea))
    )
    if call_res: return True

    return False

available_configs = {
    'rangers': {
        '1.41': {
            'sdk_env_var': 'SONIC_FRONTIERS_SDK',
            'sdk_prefix': 'RangersSDK',
            'segments': {
                'data': '.trace',
                'rdata': '.udata',
                'text': '.data',
                'denuvoized_text': '.sxdata',
            },
            'pass_allocator': True,
            'namespaces': {
                'rfl': {
                    'FxBloomParameter': ['needle', 'hh'],
                    'FxDOFParameter': ['needle', 'hh'],
                    'FxColorContrastParameter': ['needle', 'hh'],
                    'FxToneMapParameter': ['needle', 'hh'],
                    'FxCameraControlParameter': ['needle', 'hh'],
                    'FxShadowMapParameter': ['needle', 'hh'],
                    'FxShadowHeightMapParameter': ['needle', 'hh'],
                    'FxVolumetricShadowParameter': ['needle', 'hh'],
                    'FxScreenBlurParameter': ['needle', 'hh'],
                    'FxSSAOParameter': ['needle', 'hh'],
                    'FxSHLightFieldParameter': ['needle', 'hh'],
                    'FxLightScatteringParameter': ['needle', 'hh'],
                    'FxRLRParameter': ['needle', 'hh'],
                    'FxSSGIParameter': ['needle', 'hh'],
                    'FxPlanarReflectionParameter': ['needle', 'hh'],
                    'FxOcclusionCapsuleParameter': ['needle', 'hh'],
                    'FxGodrayParameter': ['needle', 'hh'],
                    'FxScreenSpaceGodrayParameter': ['needle', 'hh'],
                    'FxHeatHazeParameter': ['needle', 'hh'],
                    'FxSceneEnvironmentParameter': ['needle', 'hh'],
                    'FxRenderOption': ['needle', 'hh'],
                    'FxSGGIParameter': ['needle', 'hh'],
                    'FxTAAParameter': ['needle', 'hh'],
                    'FxEffectParameter': ['needle', 'hh'],
                    'FxAtmosphereParameter': ['needle', 'hh'],
                    'FxDensityParameter': ['needle', 'hh'],
                    'FxWindComputeParameter': ['needle', 'hh'],
                    'FxGpuEnvironmentParameter': ['needle', 'hh'],
                    'FxInteractiveWaveParameter': ['needle', 'hh'],
                    'FxChromaticAberrationParameter': ['needle', 'hh'],
                    'FxVignetteParameter': ['needle', 'hh'],
                    'FxTerrainMaterialBlendingParameter': ['needle', 'hh'],
                    'FxWeatherParameter': ['needle', 'hh'],
                    'FxColorAccessibilityFilterParameter': ['needle', 'hh'],
                    'FxCyberNoiseEffectParameter': ['needle', 'hh'],
                    'FxCyberSpaceStartNoiseParameter': ['needle', 'hh'],
                    'FxCyberNPCSSEffectRenderParameter': ['needle', 'hh'],
                    'FxDentParameter': ['gfx', 'hh'],
                    'FxFieldScanEffectRenderParameter': ['needle', 'hh'],
                    'FxSeparableSSSParameter': ['needle', 'hh'],
                    'FxRenderTargetSetting': ['gfx', 'hh'],
                    'FxAntiAliasing': ['needle', 'hh'],
                    'StageCommonAtmosphereParameter': ['gfx', 'hh'],
                    'FxLODParameter': ['needle', 'hh'],
                    'FxDetailParameter': ['needle', 'hh'],
                    'FxDynamicResolutionParameter': ['needle', 'hh'],
                    'FxPlanarProjectionShadowParameter': ['needle', 'hh'],
                    'FxSunPosAngle': ['needle', 'hh'],
                    'FxSunPosEarth': ['needle', 'hh'],
                    'FxSun': ['needle', 'hh'],
                    'FxMoon': ['needle', 'hh'],
                    'FxSkyCommon': ['needle', 'hh'],
                    'FxManualHeightFog': ['needle', 'hh'],
                    'FxHeightFog': ['needle', 'hh'],
                    'FxSebastienSky': ['needle', 'hh'],
                    'FxBrunetonSky': ['needle', 'hh'],
                    'FxBrunetonSkyNight': ['needle', 'hh'],
                    'FxDensityWindParameter': ['needle', 'hh'],
                    'FxTerrainParameter': ['needle', 'hh'],
                    'FxDropParameter': ['needle', 'hh'],
                    'FxPuddleParameter': ['needle', 'hh'],
                    'FxRippleParameter': ['needle', 'hh'],
                    'FxRainParameter': ['needle', 'hh'],
                    'FxDistanceFogParameter': ['needle', 'hh'],
                    'FxHeightFogParameter': ['needle', 'hh'],
                    'FxFogParameter': ['needle', 'hh'],
                    'FxInteractionDebugParameter': ['needle', 'hh'],
                    'FxInteractionParameter': ['needle', 'hh'],
                    'FxModelParameter': ['needle', 'hh'],
                    'FxAutoExposureParameter': ['needle', 'hh'],
                    'FxDirectionalRadialBlurParameter': ['needle', 'hh'],
                    'FxFXAAParameter': ['needle', 'hh'],
                    'FxGodrayVolumeTexture': ['needle', 'hh'],
                    'FxHBAO_Parameter': ['needle', 'hh'],
                    'FxHeightMapParameter': ['needle', 'hh'],
                    'FxLightFieldMergeParameter': ['needle', 'hh'],
                    'FxManualExposureParameter': ['needle', 'hh'],
                    'FxPlanarProjectionShadowParameter': ['needle', 'hh'],
                    'FxSMAAParameter': ['needle', 'hh'],
                    'FxSSAO_Parameter': ['needle', 'hh'],
                    'FxSSS_Parameter': ['needle', 'hh'],
                    'FxSSGIDebugParameter': ['needle', 'hh'],
                    'FxToneMapParameterFilmic': ['needle', 'hh'],
                    'FxToneMapParameterGT': ['needle', 'hh'],
                    'FxVfDepthParameter': ['needle', 'hh'],
                    'FxVfImageCircleParameter': ['needle', 'hh'],
                    'FxVfLineParameter': ['needle', 'hh'],
                    'FxWindComputeDebugParameter': ['needle', 'hh'],
                    'FxCloudBlendParameter': ['needle', 'hh'],
                    'FxCloudProcedural': ['needle', 'hh'],
                    'FxCloudShadowParameter': ['needle', 'hh'],
                    'FxCrepuscularRay': ['needle', 'hh'],
                    'FxDensityParameter': ['needle', 'hh'],
                    'FxDensityLodParameter': ['needle', 'hh'],
                    'FxDensityDebugParameter': ['needle', 'hh'],
                    'ColorDropout': ['needle', 'hh'],
                    'ColorShift': ['needle', 'hh'],
                    'DebugScreenOption': ['needle', 'hh'],
                    'FxAntiAliasing': ['needle', 'hh'],
                    'FxBloomParameter': ['needle', 'hh'],
                    'FxCameraControlParameter': ['needle', 'hh'],
                    'FxChromaticAberrationParameter': ['needle', 'hh'],
                    'FxColorAccessibilityFilterParameter': ['needle', 'hh'],
                    'FxColorContrastParameter': ['needle', 'hh'],
                    'FxCyberSpaceStartNoiseParameter': ['needle', 'hh'],
                    'StageCommonTimeProgressParameter': ['gfx', 'hh'],
                    'NeedleFxSceneConfig': ['needle', 'hh'],
                    'NeedleFxParameter': ['needle', 'hh'],
                    'NeedleFxSceneData': ['needle', 'hh'],
                },
                'resources': {
                    'ResAtomConfig': ['snd', 'hh'],
                    'ResAtomCueSheet': ['snd', 'hh'],
                    'ResMirageLight': ['gfx', 'hh'],
                    'ResMaterial': ['gfx', 'hh'],
                    'ResTerrainModel': ['gfx', 'hh'],
                    'ResModel': ['gfx', 'hh'],
                    'ResComputeShader': ['gfnd', 'hh'],
                    'ResFragmentShader': ['gfnd', 'hh'],
                    'ResVertexShader': ['gfnd', 'hh'],
                    'ResTexture': ['gfnd', 'hh'],
                    'ResLevel': ['level', 'app'],
                    'ResMasterLevel': ['level', 'app'],
                    'ResBitmapFont': ['font', 'hh'],
                    'ResScalableFontSet': ['font', 'hh'],
                    'ResReflection': ['fnd', 'hh'],
                    'Packfile': ['fnd', 'hh'],
                    'ResEffect': ['eff', 'hh'],
                },
            },
            'heuristics': {
                'looks_like_instantiator': looks_like_instantiator_rangers,
            },
            'rfl_member_types': [
                'TYPE_VOID',
                'TYPE_BOOL',
                'TYPE_SINT8',
                'TYPE_UINT8',
                'TYPE_SINT16',
                'TYPE_UINT16',
                'TYPE_SINT32',
                'TYPE_UINT32',
                'TYPE_SINT64',
                'TYPE_UINT64',
                'TYPE_FLOAT',
                'TYPE_VECTOR2',
                'TYPE_VECTOR3',
                'TYPE_VECTOR4',
                'TYPE_QUATERNION',
                'TYPE_MATRIX34',
                'TYPE_MATRIX44',
                'TYPE_POINTER',
                'TYPE_ARRAY',
                'TYPE_SIMPLE_ARRAY',
                'TYPE_ENUM',
                'TYPE_STRUCT',
                'TYPE_FLAGS',
                'TYPE_CSTRING',
                'TYPE_STRING',
                'TYPE_OBJECT_ID',
                'TYPE_POSITION',
                'TYPE_COLOR_BYTE',
                'TYPE_COLOR_FLOAT',
            ],
            'fixed_rfl_overrides': {
                '?rflClass@DetailMesh@heur@rfl@@2VRflClass@fnd@hh@@B': { 'name': 'DetailMesh', 'member_count': 2, 'parent': 0 },
                '?rflClass@OffMeshLinkParameter@heur@rfl@@2VRflClass@fnd@hh@@B': { 'name': 'OffMeshLinkParameter', 'member_count': 1, 'parent': 0 },
                '?rflClass@Partitioning@heur@rfl@@2VRflClass@fnd@hh@@B': { 'name': 'Partitioning', 'member_count': 1, 'parent': 0 },
                '?rflClass@Polygonization@heur@rfl@@2VRflClass@fnd@hh@@B': { 'name': 'Polygonization', 'member_count': 3, 'parent': 0 },
                '?rflClass@Rasterization@heur@rfl@@2VRflClass@fnd@hh@@B': { 'name': 'Rasterization', 'member_count': 2, 'parent': 0 },
                '?rflClass@Region@heur@rfl@@2VRflClass@fnd@hh@@B': { 'name': 'Region', 'member_count': 2, 'parent': 0 },
                '?rflClass@World@heur@rfl@@2VRflClass@fnd@hh@@B': { 'name': 'World', 'member_count': 2, 'parent': 0 },
                '?rflClass@FxBrunetonSky@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxBrunetonSky', 'member_count': 19, 'parent': 0 },
                '?rflClass@FxBrunetonSkyNight@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxBrunetonSkyNight', 'member_count': 8, 'parent': 0 },
                '?rflClass@FxCloudBlendParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxCloudBlendParameter', 'member_count': 4, 'parent': 0 },
                '?rflClass@FxCloudProcedural@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxCloudProcedural', 'member_count': 4, 'parent': 0 },
                '?rflClass@FxCloudShadowParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxCloudShadowParameter', 'member_count': 3, 'parent': 0 },
                '?rflClass@FxCrepuscularRay@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxCrepuscularRay', 'member_count': 4, 'parent': 0 },
                '?rflClass@FxDensityParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxDensityParameter', 'member_count': 19, 'parent': 0 },
                '?rflClass@FxDensityLodParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxDensityLodParameter', 'member_count': 5, 'parent': 0 },
                '?rflClass@FxDensityDebugParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxDensityDebugParameter', 'member_count': 14, 'parent': 0 },
                '?rflClass@ColorDropout@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'ColorDropout', 'member_count': 6, 'parent': 0 },
                '?rflClass@ColorShift@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'ColorShift', 'member_count': 4, 'parent': 0 },
                '?rflClass@DebugScreenOption@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'DebugScreenOption', 'member_count': 10, 'parent': 0 },
                '?rflClass@FxAntiAliasing@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxAntiAliasing', 'member_count': 3, 'parent': 0 },
                '?rflClass@FxBloomParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxBloomParameter', 'member_count': 5, 'parent': 0 },
                '?rflClass@FxCameraControlParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxCameraControlParameter', 'member_count': 3, 'parent': 0 },
                '?rflClass@FxChromaticAberrationParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxChromaticAberrationParameter', 'member_count': 9, 'parent': 0 },
                '?rflClass@FxColorAccessibilityFilterParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxColorAccessibilityFilterParameter', 'member_count': 9, 'parent': 0 },
                '?rflClass@FxColorContrastParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxColorContrastParameter', 'member_count': 17, 'parent': 0 },
                '?rflClass@FxCyberSpaceStartNoiseParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxCyberSpaceStartNoiseParameter', 'member_count': 11, 'parent': 0 },
                '?rflClass@FxDOFParameter@needle@hh@@2VRflClass@fnd@3@B': { 'name': 'FxDOFParameter', 'member_count': 22, 'parent': 0 },
            },
            'caption_string_addr': 0x1440B7710,
        },
    },
    'wars': {
        'latest': {
            'sdk_env_var': 'SONIC_FORCES_SDK',
            'sdk_prefix': 'WarsSDK',
            'segments': {
                'data': '.srdata',
                'rdata': '.tls',
                'text': '.xtext',
                'denuvoized_text': '.arch',
            },
            'pass_allocator': False,
            'namespaces': {
                'rfl': {
                    'FxBloomParameter': ['hh'],
                    'FxColorContrastParameter': ['hh'],
                    'FxDOFParameter': ['hh'],
                    'FxExposureParameter': ['hh'],
                    'FxToneMapParameter': ['hh'],
                    'FxShadowMapParameter': ['hh'],
                    'FxLightFieldParameter': ['hh'],
                    'FxLightScatteringParameter': ['hh'],
                    'FxOcclusionCapsuleParameter': ['hh'],
                    'FxRLRParameter': ['hh'],
                    'FxGodrayParameter': ['hh'],
                    'FxScreenSpaceGodrayParameter': ['hh'],
                    'FxEffectParameter': ['hh'],
                    'FxDebugScreenOption': ['hh'],
                    'FxRenderOption': ['hh'],
                    'FxHDROption': ['hh'],
                    'FxSGGIParameter': ['hh'],
                    'FxSSAOParameter': ['hh'],
                    'FxSHLightFieldParameter': ['hh'],
                    'FxScreenBlurParameter': ['hh'],
                    'FxHeatHazeParameter': ['hh'],
                    'FxSceneEnvironmentParameter': ['hh'],
                    'FxTAAParameter': ['hh'],
                    'NeedleFxParameter': ['hh'],
                    'FxRenderTargetSetting': ['hh'],
                    'FxAntiAliasing': ['hh'],
                    'NeedleFxSceneConfig': ['hh'],
                    'StageCommonParameter': ['hh'],
                    'StageCameraParameter': ['hh'],
                    'StageConfig': ['hh'],
                    'NeedleFxSceneData': ['hh'],
                },
                'resources': {
                    'ResAtomConfig': ['snd', 'hh'],
                    'ResAtomCueSheet': ['snd', 'hh'],
                    'ResMirageLight': ['gfx', 'hh'],
                    'ResMaterial': ['gfx', 'hh'],
                    'ResTerrainModel': ['gfx', 'hh'],
                    'ResModel': ['gfx', 'hh'],
                    'ResComputeShader': ['gfnd', 'hh'],
                    'ResFragmentShader': ['gfnd', 'hh'],
                    'ResVertexShader': ['gfnd', 'hh'],
                    'ResTexture': ['gfnd', 'hh'],
                    'ResLevel': ['level', 'app'],
                    'ResMasterLevel': ['level', 'app'],
                    'ResBitmapFont': ['font', 'hh'],
                    'ResScalableFontSet': ['font', 'hh'],
                    'ResReflection': ['fnd', 'hh'],
                    'Packfile': ['fnd', 'hh'],
                    'ResEffect': ['eff', 'hh'],
                },
            },
            'resource_namespaces': {},
            'allocator_addresses': (0x14071B3A0, 0x1406B79B0, 0x14071B410),
            'heuristics': {
                'looks_like_instantiator': looks_like_instantiator_wars,
            },
            'rfl_member_types': [
                'TYPE_VOID',
                'TYPE_BOOL',
                'TYPE_SINT8',
                'TYPE_UINT8',
                'TYPE_SINT16',
                'TYPE_UINT16',
                'TYPE_SINT32',
                'TYPE_UINT32',
                'TYPE_SINT64',
                'TYPE_UINT64',
                'TYPE_FLOAT',
                'TYPE_VECTOR2',
                'TYPE_VECTOR3',
                'TYPE_VECTOR4',
                'TYPE_QUATERNION',
                'TYPE_MATRIX34',
                'TYPE_MATRIX44',
                'TYPE_POINTER',
                'TYPE_ARRAY',
                'TYPE_OLD_ARRAY',
                'TYPE_SIMPLE_ARRAY',
                'TYPE_ENUM',
                'TYPE_STRUCT',
                'TYPE_FLAGS',
                'TYPE_CSTRING',
                'TYPE_STRING',
                'TYPE_OBJECT_ID',
                'TYPE_POSITION',
                'TYPE_COLOR_BYTE',
                'TYPE_COLOR_FLOAT',
            ],
            'fixed_rfl_overrides': {},
        },
    },
}

def configure_rangers_analysis(game, version):
    global rangers_analysis_config

    rangers_analysis_config = available_configs[game][version]

known_dbs = {
    b'\x99\x89\x9acV\xdeOA\xea\xf9%\xbe`b\xf0\x13mI\xba\xc3\xf7Q|\xdc\x16\x14\x10\x84!\x86\x00\xbe': { 'game': 'rangers', 'version': '1.41' },
    b'\x84\xab!YF\xef{sFyZ\x13\x0c\xff\x12\x9ck|e[Y\x1a\x015u\xb3\xf4\x1a/\xec\x13\x14': { 'game': 'wars', 'version': 'latest' },
}

def autoconfigure_rangers_analysis():
    if db_desc := known_dbs[retrieve_input_file_sha256()]:
        configure_rangers_analysis(db_desc['game'], db_desc['version'])
    else:
        raise Exception('Unknown database, cannot autoconfigure.')
