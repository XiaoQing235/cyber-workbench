cmake_minimum_required(VERSION 3.20)
project(ctf_bkcrack LANGUAGES CXX)

if(NOT DEFINED BKCRACK_SOURCE)
  message(FATAL_ERROR "BKCRACK_SOURCE is required")
endif()

add_executable(bkcrack
  adapter.cpp
  ${BKCRACK_SOURCE}/src/Attack.cpp
  ${BKCRACK_SOURCE}/src/Crc32Tab.cpp
  ${BKCRACK_SOURCE}/src/Data.cpp
  ${BKCRACK_SOURCE}/src/Keys.cpp
  ${BKCRACK_SOURCE}/src/KeystreamTab.cpp
  ${BKCRACK_SOURCE}/src/log.cpp
  ${BKCRACK_SOURCE}/src/MultTab.cpp
  ${BKCRACK_SOURCE}/src/Progress.cpp
  ${BKCRACK_SOURCE}/src/types.cpp
  ${BKCRACK_SOURCE}/src/Zreduction.cpp
)
target_include_directories(bkcrack PRIVATE ${BKCRACK_SOURCE}/include)
target_compile_features(bkcrack PRIVATE cxx_std_17)
set_target_properties(bkcrack PROPERTIES RUNTIME_OUTPUT_DIRECTORY /out SUFFIX ".js")
target_link_options(bkcrack PRIVATE
  --no-entry
  -sFILESYSTEM=0
  -sALLOW_MEMORY_GROWTH=1
  -sSTACK_SIZE=1048576
  -sMODULARIZE=1
  -sEXPORT_ES6=1
  -sENVIRONMENT=worker
  -sASSERTIONS=0
  "-sEXPORTED_FUNCTIONS=[\"_malloc\",\"_free\",\"_bk_error\",\"_bk_reset\",\"_bk_prepare\",\"_bk_step\",\"_bk_cursor\",\"_bk_key_x\",\"_bk_key_y\",\"_bk_key_z\",\"_bk_self_test\"]"
  "-sEXPORTED_RUNTIME_METHODS=[\"UTF8ToString\",\"writeArrayToMemory\"]"
)