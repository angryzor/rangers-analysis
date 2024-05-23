import rangers_analysis.lib.segments

rangers_analysis_config = None

available_configs = {
    'rangers': {
        '1.41': {
            'segments': {
                'data': '.srdata',
                'rdata': '.tls',
                'text': '.xtext',
                'denuvoized_text': '.arch',
            },
            'pass_allocator': True,
        },
    },
    'wars': {
        'latest': {
            'segments': {
                'data': '.srdata',
                'rdata': '.tls',
                'text': '.xtext',
                'denuvoized_text': '.arch',
            },
            'pass_allocator': False,
        },
    },
}

def configure_rangers_analysis(game, version):
    global rangers_analysis_config

    rangers_analysis_config = available_configs[game][version]
