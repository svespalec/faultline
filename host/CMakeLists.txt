add_executable( host main.cxx )

target_link_libraries( host PRIVATE shared )
target_precompile_headers( host PRIVATE ${CMAKE_SOURCE_DIR}/shared/stdafx.hxx )
