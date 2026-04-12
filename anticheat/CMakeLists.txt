add_library( anticheat SHARED
  main.cxx
  faultline.cxx
  module_checker.cxx
  stack_walk.cxx
  working_set_engine.cxx
)

target_link_libraries( anticheat PRIVATE shared )
target_include_directories( anticheat PRIVATE ${CMAKE_SOURCE_DIR} )
target_precompile_headers( anticheat PRIVATE ${CMAKE_SOURCE_DIR}/shared/stdafx.hxx )
target_compile_definitions( anticheat PRIVATE FAULTLINE_EXPORT )
target_compile_options( anticheat PRIVATE /W4 /WX )
